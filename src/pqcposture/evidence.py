"""Evidence: immutable per-handshake records, and what can be derived from them.

The discipline this module enforces is the whole point of Phase 1: an
observation records what happened on one connection at one moment. Nothing is
merged, averaged, or promoted to a claim about "the endpoint". Aggregation
happens at read time and is always reversible.

The consequence worth internalising: absence of an observation is never
evidence of absence. A group that was never successfully probed against a
given peer is NOT_OBSERVED, not UNSUPPORTED. Behind a load balancer those are
completely different statements, and collapsing them is how a scanner reports
that a pool supports hybrid KEX when only one of four members does.
"""

from __future__ import annotations

import base64
import enum
import hashlib
import re
from dataclasses import dataclass, field

_PEM_RE = re.compile(
    r"-----BEGIN CERTIFICATE-----(.+?)-----END CERTIFICATE-----", re.S)


class Support(enum.Enum):
    OBSERVED_SUPPORTED = "observed_supported"
    OBSERVED_REJECTED = "observed_rejected"
    NOT_OBSERVED = "not_observed"


def leaf_fingerprint(s_client_output: str) -> str | None:
    """SHA-256 over the leaf certificate DER.

    Matches `openssl x509 -fingerprint -sha256` and costs no extra handshake:
    s_client already prints the leaf PEM in its default output.
    """
    match = _PEM_RE.search(s_client_output)
    if not match:
        return None
    try:
        der = base64.b64decode("".join(match.group(1).split()))
    except (ValueError, TypeError):
        return None
    return hashlib.sha256(der).hexdigest()


@dataclass(frozen=True)
class PeerIdentity:
    """What we can tell about the peer that answered one connection.

    Certificate fingerprint is the primary discriminator. It is deliberately
    weak on its own: pool members commonly share one wildcard certificate, so
    identical fingerprints do NOT prove a single peer. Behavioural divergence
    is the stronger signal, and is tracked separately.
    """
    cert_fingerprint: str | None
    subject: str | None = None
    issuer: str | None = None
    not_after: str | None = None
    key_algorithm: str | None = None
    key_bits: int | None = None
    signature_algorithm: str | None = None
    chain_length: int | None = None

    @property
    def short(self) -> str:
        if not self.cert_fingerprint:
            return "unidentified"
        return self.cert_fingerprint[:12]


@dataclass
class Observation:
    """One handshake attempt. Immutable evidence."""
    endpoint: str              # host:port as probed
    role: str                  # frontend | backend
    pass_index: int            # which repeat pass this belongs to
    group_offered: str         # a group name, or __default__ / __realistic__
    outcome: str               # models.Outcome value
    observed_at: str = ""
    negotiated_group: str | None = None
    cipher: str | None = None
    tls_version: str | None = None
    alert: str | None = None
    detail: str | None = None
    bytes_written: int | None = None
    peer: PeerIdentity | None = None
    duration_ms: int = 0

    @property
    def succeeded(self) -> bool:
        return self.outcome == "supported"

    @property
    def peer_key(self) -> str:
        return self.peer.short if self.peer else "unidentified"


@dataclass
class EndpointEvidence:
    """All observations for one probed address, plus read-time aggregations."""
    endpoint: str
    role: str
    declared_label: str | None = None
    resolved_ip: str | None = None
    passes: int = 0
    observations: list[Observation] = field(default_factory=list)

    # ---- peers ----------------------------------------------------------

    def peers(self) -> dict[str, PeerIdentity]:
        found: dict[str, PeerIdentity] = {}
        for obs in self.observations:
            if obs.peer and obs.peer.cert_fingerprint:
                found.setdefault(obs.peer.short, obs.peer)
        return found

    def distinct_peer_count(self) -> int:
        return len(self.peers())

    # ---- support matrix -------------------------------------------------

    def support_matrix(self) -> dict[str, dict[str, str]]:
        """{peer_key: {group: Support.value}} over real group probes only."""
        matrix: dict[str, dict[str, str]] = {}
        for obs in self.observations:
            if obs.group_offered.startswith("__"):
                continue
            row = matrix.setdefault(obs.peer_key, {})
            current = row.get(obs.group_offered)
            new = (Support.OBSERVED_SUPPORTED.value if obs.succeeded
                   else Support.OBSERVED_REJECTED.value
                   if obs.outcome in ("rejected", "protocol_unsupported")
                   else Support.NOT_OBSERVED.value)
            # A single success outranks any number of inconclusive attempts;
            # an explicit rejection outranks "never got an answer".
            rank = {Support.NOT_OBSERVED.value: 0,
                    Support.OBSERVED_REJECTED.value: 1,
                    Support.OBSERVED_SUPPORTED.value: 2}
            if current is None or rank[new] > rank[current]:
                row[obs.group_offered] = new
        return matrix

    def groups_observed_supported(self, peer_key: str | None = None) -> set[str]:
        matrix = self.support_matrix()
        rows = [matrix[peer_key]] if peer_key and peer_key in matrix \
            else list(matrix.values())
        result: set[str] = set()
        for row in rows:
            result |= {g for g, state in row.items()
                       if state == Support.OBSERVED_SUPPORTED.value}
        return result

    # ---- consistency ----------------------------------------------------

    def inconsistencies(self) -> list[str]:
        """Groups whose outcome differed across passes at the same address.

        This is the strongest available proof of a heterogeneous pool, and it
        holds even when every member presents the same certificate. One
        ClientHello answered two different ways from one address means more
        than one TLS configuration is live behind it.
        """
        seen: dict[str, set[bool]] = {}
        for obs in self.observations:
            if obs.group_offered.startswith("__"):
                continue
            if obs.outcome in ("client_unsupported", "dns_failed",
                               "connect_refused"):
                continue
            seen.setdefault(obs.group_offered, set()).add(obs.succeeded)
        return sorted(g for g, outcomes in seen.items() if len(outcomes) > 1)

    def reachable(self) -> bool:
        return any(obs.succeeded for obs in self.observations)

    def negotiated_by_default(self) -> str | None:
        for obs in self.observations:
            if obs.group_offered == "__default__" and obs.succeeded:
                return obs.negotiated_group
        return None

    def negotiated_realistic(self) -> str | None:
        for obs in self.observations:
            if obs.group_offered == "__realistic__" and obs.succeeded:
                return obs.negotiated_group
        return None

    def tls_versions_seen(self) -> set[str]:
        return {obs.tls_version for obs in self.observations
                if obs.succeeded and obs.tls_version}


def coverage_note(passes: int, distinct_peers: int) -> str | None:
    """Whether the repeat count plausibly saw the whole pool.

    Hitting every one of N members by random balancing needs roughly N·ln(N)
    draws, and that is the optimistic case — it assumes the balancer actually
    re-selects. Source-address persistence, the default on plenty of F5
    virtual servers, pins every connection from this scanner to one member no
    matter how many passes are run.
    """
    if distinct_peers <= 1:
        if passes <= 1:
            return ("one pass, one peer identity — this says nothing about "
                    "pool size or uniformity")
        return ("all passes returned one peer identity. Either the pool is "
                "uniform, or connection persistence pinned every probe to the "
                "same member. Those are indistinguishable from a single "
                "source address.")
    if passes < distinct_peers * 3:
        return (f"{distinct_peers} peer identities seen in {passes} passes; "
                f"coverage is likely incomplete — more members may exist")
    return None
