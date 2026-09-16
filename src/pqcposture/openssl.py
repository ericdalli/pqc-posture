"""Locating a usable OpenSSL, detecting what it can offer, and parsing
`s_client` output.

Why subprocess at all: Python's `ssl` module is bound to whatever libssl the
interpreter was linked against, and it exposes no API for setting the TLS 1.3
supported_groups list to a hybrid KEM. `SSLContext.set_ecdh_curve()` only
accepts named EC curves. Even on a 3.5-linked build there is no way to ask for
X25519MLKEM768, so probing has to go through the CLI.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
from dataclasses import dataclass

from .models import GROUP_CATALOG, LEGACY_HYBRID_ALIASES, Outcome

MIN_VERSION = (3, 5, 0)

_VERSION_RE = re.compile(r"OpenSSL\s+(\d+)\.(\d+)\.(\d+)")
# 3.2+ prints this line; it is the authoritative answer.
_NEGOTIATED_RE = re.compile(r"^Negotiated TLS1\.3 group:\s*(\S+)", re.M)
# Fallback for older clients and for -brief output.
_TEMP_KEY_RE = re.compile(r"^Server Temp Key:\s*(.+?)\s*$", re.M)
_CIPHER_RE = re.compile(r"^New,\s*(\S+),\s*Cipher is\s*(\S+)", re.M)
_BRIEF_PROTO_RE = re.compile(r"^Protocol version:\s*(\S+)", re.M)
_BRIEF_CIPHER_RE = re.compile(r"^Ciphersuite:\s*(\S+)", re.M)
_PROTOCOL_LINE_RE = re.compile(r"^\s*Protocol\s*:\s*(\S+)", re.M)
_BYTES_RE = re.compile(r"SSL handshake has read (\d+) bytes and written (\d+) bytes")
_ALERT_RE = re.compile(r"(?:alert number (\d+)|alert ([a-z_ ]+?)(?::|$))", re.I)
_VERIFY_RE = re.compile(r"^Verify return code:\s*(\d+)\s*\((.*?)\)", re.M)
_HRR_RE = re.compile(r"hello_retry_request|HelloRetryRequest", re.I)

# Chain summary lines emitted by s_client, e.g.
#   a:PKEY: rsaEncryption, 2048 (bit); sigalg: RSA-SHA256
_CHAIN_PKEY_RE = re.compile(
    r"^\s*a:PKEY:\s*([^,]+),\s*(\d+)\s*\(bit\);\s*sigalg:\s*(\S+)", re.M)
_CHAIN_VALIDITY_RE = re.compile(
    r"^\s*v:NotBefore:\s*(.+?);\s*NotAfter:\s*(.+?)\s*$", re.M)
_CHAIN_ENTRY_RE = re.compile(r"^\s*(\d+)\s+s:(.*)$", re.M)
_ISSUER_RE = re.compile(r"^\s*i:(.*)$", re.M)


class OpenSSLNotUsable(RuntimeError):
    pass


@dataclass
class OpenSSLInfo:
    path: str
    version_string: str
    version: tuple[int, int, int]
    groups: list[str]          # catalog groups this client can actually offer
    supports_trace: bool

    @property
    def meets_minimum(self) -> bool:
        return self.version >= MIN_VERSION


def _run(argv: list[str], timeout: float = 10.0,
         stdin_data: bytes | None = None) -> subprocess.CompletedProcess:
    return subprocess.run(
        argv,
        input=stdin_data if stdin_data is not None else b"",
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=timeout,
        env={**os.environ, "LC_ALL": "C"},
    )


def discover(explicit_path: str | None = None,
             require_minimum: bool = True) -> OpenSSLInfo:
    """Find an OpenSSL that can offer hybrid groups.

    Search order: explicit path, $PQC_OPENSSL, common 3.5 install prefixes,
    then $PATH. Distro OpenSSL is usually 3.0/3.2 and cannot do ML-KEM, so a
    side-by-side 3.5 build is the normal case.
    """
    candidates: list[str] = []
    if explicit_path:
        candidates.append(explicit_path)
    if os.environ.get("PQC_OPENSSL"):
        candidates.append(os.environ["PQC_OPENSSL"])
    candidates += [
        "/usr/local/ssl/bin/openssl",
        "/opt/openssl-3.5/bin/openssl",
        "/usr/local/opt/openssl@3.5/bin/openssl",
        "/opt/homebrew/opt/openssl@3.5/bin/openssl",
    ]
    found = shutil.which("openssl")
    if found:
        candidates.append(found)

    best: OpenSSLInfo | None = None
    for path in candidates:
        if not path or not os.path.isfile(path) or not os.access(path, os.X_OK):
            continue
        info = _inspect(path)
        if info is None:
            continue
        if info.meets_minimum:
            return info
        if best is None or info.version > best.version:
            best = info

    if best is None:
        raise OpenSSLNotUsable(
            "No usable openssl binary found. Install OpenSSL 3.5+ and point "
            "PQC_OPENSSL at it.")
    if require_minimum:
        raise OpenSSLNotUsable(
            f"{best.path} is {best.version_string}; pqc-posture needs 3.5.0+ "
            f"for ML-KEM groups. Set PQC_OPENSSL to a 3.5 build, or pass "
            f"--allow-old-openssl to run classical-only probes.")
    return best


def _inspect(path: str) -> OpenSSLInfo | None:
    try:
        proc = _run([path, "version"], timeout=5)
    except (OSError, subprocess.SubprocessError):
        return None
    text = proc.stdout.decode(errors="replace").strip()
    m = _VERSION_RE.search(text)
    if not m:
        return None
    version = (int(m.group(1)), int(m.group(2)), int(m.group(3)))
    return OpenSSLInfo(
        path=path,
        version_string=text,
        version=version,
        groups=detect_groups(path),
        supports_trace=_has_trace(path),
    )


def _has_trace(path: str) -> bool:
    try:
        proc = _run([path, "s_client", "-help"], timeout=5)
    except (OSError, subprocess.SubprocessError):
        return False
    return b"-trace" in proc.stdout + proc.stderr


def detect_groups(path: str) -> list[str]:
    """Which catalog groups this client can offer.

    Prefers `openssl list -tls-groups` (3.5+). Falls back to asking s_client to
    accept the group against an address it will never reach: a bad group name
    fails during option parsing, before any socket work, and that difference is
    visible in the exit path.
    """
    wanted = {g.name.lower(): g.name for g in (*GROUP_CATALOG, *LEGACY_HYBRID_ALIASES)}
    try:
        proc = _run([path, "list", "-tls-groups", "-all"], timeout=10)
        blob = (proc.stdout + proc.stderr).decode(errors="replace")
    except (OSError, subprocess.SubprocessError):
        blob = ""

    if "Unknown option" not in blob and blob.strip():
        # Providers spell the same group several ways (X25519MLKEM768,
        # x25519_mlkem768, X25519-MLKEM768), so compare with separators and
        # case stripped out.
        def norm(value: str) -> str:
            return value.lower().replace("_", "").replace("-", "")

        present = {norm(t) for t in re.findall(r"[A-Za-z0-9_\-]+", blob)}
        order = list(wanted.values())
        seen = [canonical for canonical in order if norm(canonical) in present]
        if seen:
            return sorted(seen, key=order.index)

    return [name for key, name in wanted.items() if _group_accepted(path, name)]


# Emitted by the *local* client when it does not know a group name. The
# exact wording varies by version, which is why several are matched.
_LOCAL_GROUP_ERRORS = (
    "call to ssl_conf_cmd",       # 3.0-3.5: Call to SSL_CONF_cmd(-groups, X) failed
    "error with command",
    "unknown group",
    "invalid group",
    "no supported groups",
    "error setting",
)


def _group_accepted(path: str, group: str) -> bool:
    """True if the local client recognises `group` as an option value."""
    try:
        proc = _run(
            [path, "s_client", "-groups", group, "-connect", "127.0.0.1:1"],
            timeout=5)
    except subprocess.TimeoutExpired:
        return True
    except (OSError, subprocess.SubprocessError):
        return False
    err = (proc.stdout + proc.stderr).decode(errors="replace").lower()
    return not any(marker in err for marker in _LOCAL_GROUP_ERRORS)


# --------------------------------------------------------------------------
# Output parsing
# --------------------------------------------------------------------------

def parse_negotiated_group(text: str) -> str | None:
    m = _NEGOTIATED_RE.search(text)
    if m:
        return m.group(1)
    m = _TEMP_KEY_RE.search(text)
    if m:
        return _normalise_temp_key(m.group(1))
    return None


def _normalise_temp_key(body: str) -> str | None:
    """`Server Temp Key:` has two shapes.

    Named-group form: "X25519MLKEM768, 192 bits" — the name is the group.
    Generic form:     "ECDH, P-256, 256 bits"    — the first field is only the
    algorithm family, and the curve in the second field is the real answer.
    """
    fields = [f.strip() for f in body.split(",")]
    if not fields:
        return None
    head = fields[0]
    if head.upper() in ("ECDH", "DH", "ECDHE", "DHE") and len(fields) > 1:
        return fields[1]
    return head or None


def parse_cipher_and_version(text: str) -> tuple[str | None, str | None]:
    """Returns (tls_version, cipher)."""
    m = _CIPHER_RE.search(text)
    if m:
        return m.group(1), m.group(2)
    proto = _BRIEF_PROTO_RE.search(text)
    cipher = _BRIEF_CIPHER_RE.search(text)
    if proto or cipher:
        return (proto.group(1) if proto else None,
                cipher.group(1) if cipher else None)
    m = _PROTOCOL_LINE_RE.search(text)
    return (m.group(1) if m else None), None


def parse_bytes_written(text: str) -> int | None:
    m = _BYTES_RE.search(text)
    return int(m.group(2)) if m else None


def parse_verify(text: str) -> tuple[bool | None, str | None]:
    m = _VERIFY_RE.search(text)
    if not m:
        return None, None
    code, desc = int(m.group(1)), m.group(2)
    return code == 0, (None if code == 0 else desc)


def saw_hello_retry_request(text: str) -> bool:
    return bool(_HRR_RE.search(text))


def handshake_succeeded(text: str) -> bool:
    """A handshake completed if the peer's Finished was processed.

    `-brief` reports CONNECTION ESTABLISHED; full mode prints the "New, TLSvX"
    summary and the byte counts. Certificate verification failure does not mean
    handshake failure, and is recorded separately.
    """
    if "CONNECTION ESTABLISHED" in text:
        return True
    m = _CIPHER_RE.search(text)
    if m:
        # A *failed* handshake still prints this line, as
        # "New, (NONE), Cipher is (NONE)", and still prints byte counts and
        # "Verify return code: 0 (ok)". Only a real ciphersuite means success.
        version, cipher = m.group(1), m.group(2)
        return "(NONE)" not in cipher and "(NONE)" not in version
    return False


ALERT_NAMES = {
    "40": "handshake_failure",
    "47": "illegal_parameter",
    "70": "protocol_version",
    "71": "insufficient_security",
    "80": "internal_error",
    "112": "unrecognized_name",
}


def classify_failure(text: str, returncode: int) -> tuple[str, str | None, str]:
    """Map s_client failure output onto (Outcome, alert_name, detail).

    The operationally important split: a TLS alert means the peer understood
    the ClientHello and declined. A reset or silent drop with no alert means
    something on the path could not carry the ClientHello at all — which for a
    1216-byte ML-KEM key share is almost always a middlebox or MTU problem,
    not a server capability gap.
    """
    low = text.lower()
    first_line = next(
        (ln.strip() for ln in text.splitlines() if ln.strip()), "")

    if "name or service not known" in low or "getaddrinfo" in low \
            or "nodename nor servname" in low:
        return Outcome.DNS_FAILED.value, None, "DNS resolution failed"

    if "connection refused" in low or "errno=111" in low:
        return Outcome.CONNECT_REFUSED.value, None, "TCP connection refused"

    if any(marker in low for marker in _LOCAL_GROUP_ERRORS):
        # Critical ordering: this is our own client refusing the option, before
        # a packet is sent. Left unhandled it looks identical to a silent drop
        # and would fabricate a middlebox-intolerance finding.
        return (Outcome.CLIENT_UNSUPPORTED.value, None,
                "local OpenSSL does not support this group")

    if "unsupported protocol" in low or "wrong version number" in low \
            or "no protocols available" in low:
        return (Outcome.PROTOCOL_UNSUPPORTED.value, None,
                "peer does not support the requested TLS version")

    alert = None
    m = _ALERT_RE.search(text)
    if m:
        if m.group(1):
            alert = ALERT_NAMES.get(m.group(1), f"alert_{m.group(1)}")
        else:
            alert = m.group(2).strip().replace(" ", "_")

    if alert:
        if alert == "protocol_version":
            return (Outcome.PROTOCOL_UNSUPPORTED.value, alert,
                    "peer rejected the TLS version")
        return (Outcome.REJECTED.value, alert,
                f"peer sent TLS alert: {alert}")

    if "connection reset" in low or "errno=104" in low \
            or "unexpected eof" in low or "reset by peer" in low:
        return (Outcome.TRANSPORT_FAILED.value, None,
                "connection reset with no TLS alert")

    if returncode != 0:
        return Outcome.TRANSPORT_FAILED.value, None, first_line or "handshake did not complete"

    return Outcome.ERROR.value, None, first_line or "unrecognised failure"


def parse_chain(text: str) -> dict:
    """Pull leaf certificate facts out of the s_client chain summary.

    Uses the chain block s_client already prints rather than re-invoking
    `openssl x509`, which saves a process per target.
    """
    out: dict = {}
    entries = _CHAIN_ENTRY_RE.findall(text)
    if entries:
        out["chain_length"] = len(entries)
        out["subject"] = entries[0][1].strip()

    block_start = text.find("Certificate chain")
    if block_start != -1:
        block = text[block_start:]
        issuer = _ISSUER_RE.search(block)
        if issuer:
            out["issuer"] = issuer.group(1).strip()
        pkey = _CHAIN_PKEY_RE.search(block)
        if pkey:
            out["key_algorithm"] = pkey.group(1).strip()
            out["key_bits"] = int(pkey.group(2))
            out["signature_algorithm"] = pkey.group(3).strip()
        validity = _CHAIN_VALIDITY_RE.search(block)
        if validity:
            out["not_before"] = validity.group(1).strip()
            out["not_after"] = validity.group(2).strip()

    if "subject" not in out:
        m = re.search(r"^subject=(.*)$", text, re.M)
        if m:
            out["subject"] = m.group(1).strip()
    if "issuer" not in out:
        m = re.search(r"^issuer=(.*)$", text, re.M)
        if m:
            out["issuer"] = m.group(1).strip()
    return out
