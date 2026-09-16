"""Data model and group catalog for pqc-posture.

The JSON emitted from these dataclasses is a contract: Phase 3 (the GitHub
Actions gate) diffs two reports and fails on regression. Fields are therefore
split into *stable* facts (safe to diff) and *volatile* fields (timestamps,
durations, resolved IP) which the gate must ignore. See VOLATILE_FIELDS.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass, field, asdict
from typing import Any

SCHEMA_VERSION = 1

# Fields a regression gate must NOT diff on. Dotted paths, relative to a
# target result. Phase 3 strips these before comparing.
VOLATILE_FIELDS = (
    "started_at",
    "finished_at",
    "duration_ms",
    "resolved_ip",
    "probes.*.duration_ms",
    "certificate.days_remaining",
)


class GroupKind(enum.Enum):
    HYBRID = "hybrid"          # classical + PQ KEM concatenated
    PURE_PQ = "pure_pq"        # ML-KEM alone, no classical hedge
    CLASSICAL_EC = "classical_ec"
    CLASSICAL_FF = "classical_ff"


@dataclass(frozen=True)
class GroupSpec:
    name: str
    kind: GroupKind
    description: str
    # Approximate ClientHello key_share size in bytes. Drives large-ClientHello
    # interop analysis: anything over ~1200 pushes a ClientHello past a single
    # 1500-byte MTU segment, which is where middlebox intolerance shows up.
    key_share_bytes: int


# OpenSSL 3.5 names. Availability is feature-detected at runtime, so listing a
# group here does not mean the local client can offer it.
GROUP_CATALOG: tuple[GroupSpec, ...] = (
    # Hybrid — the ones that actually matter for harvest-now-decrypt-later.
    GroupSpec("X25519MLKEM768", GroupKind.HYBRID,
              "X25519 + ML-KEM-768 (browser default)", 1216),
    GroupSpec("SecP256r1MLKEM768", GroupKind.HYBRID,
              "P-256 + ML-KEM-768 (FIPS-friendly)", 1249),
    GroupSpec("SecP384r1MLKEM1024", GroupKind.HYBRID,
              "P-384 + ML-KEM-1024", 1665),
    # Pure PQ — no classical hedge. Rare in production; probe to characterise.
    GroupSpec("MLKEM512", GroupKind.PURE_PQ, "ML-KEM-512 standalone", 800),
    GroupSpec("MLKEM768", GroupKind.PURE_PQ, "ML-KEM-768 standalone", 1184),
    GroupSpec("MLKEM1024", GroupKind.PURE_PQ, "ML-KEM-1024 standalone", 1568),
    # Classical baseline — needed to distinguish "no PQ support" from "endpoint
    # or path is broken".
    GroupSpec("X25519", GroupKind.CLASSICAL_EC, "X25519", 32),
    GroupSpec("secp256r1", GroupKind.CLASSICAL_EC, "NIST P-256", 65),
    GroupSpec("secp384r1", GroupKind.CLASSICAL_EC, "NIST P-384", 97),
    GroupSpec("secp521r1", GroupKind.CLASSICAL_EC, "NIST P-521", 133),
    GroupSpec("X448", GroupKind.CLASSICAL_EC, "X448", 56),
    GroupSpec("ffdhe2048", GroupKind.CLASSICAL_FF, "FFDHE 2048", 256),
    GroupSpec("ffdhe3072", GroupKind.CLASSICAL_FF, "FFDHE 3072", 384),
)

# Pre-standard hybrid names from oqs-provider builds. Only probed if the local
# provider exposes them; OpenSSL 3.5 alone will not.
LEGACY_HYBRID_ALIASES: tuple[GroupSpec, ...] = (
    GroupSpec("X25519Kyber768Draft00", GroupKind.HYBRID,
              "X25519 + Kyber-768 draft (pre-FIPS-203)", 1216),
    GroupSpec("SecP256r1Kyber768Draft00", GroupKind.HYBRID,
              "P-256 + Kyber-768 draft (pre-FIPS-203)", 1249),
    GroupSpec("x25519_kyber768", GroupKind.HYBRID,
              "X25519 + Kyber-768 draft, oqs naming", 1216),
)

BY_NAME: dict[str, GroupSpec] = {
    g.name.lower(): g for g in (*GROUP_CATALOG, *LEGACY_HYBRID_ALIASES)
}


def kind_of(group_name: str) -> GroupKind | None:
    spec = BY_NAME.get(group_name.lower())
    return spec.kind if spec else None


def is_quantum_resistant(group_name: str) -> bool:
    return kind_of(group_name) in (GroupKind.HYBRID, GroupKind.PURE_PQ)


class Outcome(enum.Enum):
    """Why a probe ended the way it did.

    The distinction that matters most operationally is REJECTED (server sent a
    TLS alert — it understood us and said no) versus TRANSPORT_FAILED (nothing
    came back, or the connection was torn down). The second is the fingerprint
    of a middlebox that cannot cope with a large ClientHello, and it is a
    completely different remediation path from "the server lacks the group".
    """
    SUPPORTED = "supported"
    REJECTED = "rejected"                  # clean TLS alert from the peer
    TRANSPORT_FAILED = "transport_failed"   # RST / silent drop mid-handshake
    TIMEOUT = "timeout"
    CONNECT_REFUSED = "connect_refused"
    DNS_FAILED = "dns_failed"
    PROTOCOL_UNSUPPORTED = "protocol_unsupported"
    CLIENT_UNSUPPORTED = "client_unsupported"  # our OpenSSL lacks the group
    ERROR = "error"


@dataclass
class ProbeResult:
    group: str
    outcome: str
    negotiated_group: str | None = None
    cipher: str | None = None
    tls_version: str | None = None
    bytes_written: int | None = None   # ClientHello + client Finished, approx
    alert: str | None = None
    detail: str | None = None
    duration_ms: int = 0

    @property
    def supported(self) -> bool:
        return self.outcome == Outcome.SUPPORTED.value


@dataclass
class ProtocolSupport:
    tls1_3: bool | None = None
    tls1_2: bool | None = None
    tls1_1: bool | None = None
    tls1_0: bool | None = None
    notes: list[str] = field(default_factory=list)


@dataclass
class CertificateInfo:
    subject: str | None = None
    issuer: str | None = None
    key_algorithm: str | None = None
    key_bits: int | None = None
    signature_algorithm: str | None = None
    not_before: str | None = None
    not_after: str | None = None
    days_remaining: int | None = None
    chain_length: int | None = None
    verify_ok: bool | None = None
    verify_error: str | None = None


@dataclass
class Finding:
    code: str
    severity: str  # info | low | medium | high
    message: str


@dataclass
class TargetResult:
    host: str
    port: int
    sni: str
    resolved_ip: str | None = None
    reachable: bool = False
    protocols: ProtocolSupport = field(default_factory=ProtocolSupport)
    default_negotiated_group: str | None = None
    preferred_group_realistic: str | None = None
    hybrid_supported: bool = False
    hybrid_preferred: bool = False
    supported_groups: list[str] = field(default_factory=list)
    probes: list[ProbeResult] = field(default_factory=list)
    certificate: CertificateInfo = field(default_factory=CertificateInfo)
    large_clienthello_suspected: bool = False
    findings: list[Finding] = field(default_factory=list)
    score: int = 0
    grade: str = "F"
    duration_ms: int = 0

    @property
    def label(self) -> str:
        return f"{self.host}:{self.port}"


@dataclass
class ScanReport:
    schema_version: int = SCHEMA_VERSION
    tool_version: str = "0.1.0"
    openssl_version: str = ""
    openssl_path: str = ""
    client_groups_available: list[str] = field(default_factory=list)
    started_at: str = ""
    finished_at: str = ""
    targets: list[TargetResult] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
