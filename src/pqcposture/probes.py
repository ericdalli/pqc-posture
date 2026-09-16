"""Individual TLS probes.

Probe strategy, and why it looks like this:

1. *Capability* probes offer exactly one group. If the handshake completes, the
   server supports that group — unambiguously, with no inference about
   preference order. This costs one handshake per group, which is why probes
   for a single target run serially (see scanner.py) rather than opening a
   dozen simultaneous connections into someone's WAF.

2. A *default* probe uses the client's own default group list, which on 3.5 is
   hybrid-first. This answers "what does a current client actually get today".

3. A *realistic* probe offers a browser-shaped list. Chrome offers
   X25519MLKEM768 and X25519; a server that supports only the latter will send
   HelloRetryRequest. Comparing the realistic result against the capability map
   separates "supports hybrid" from "prefers hybrid", which are different
   conversations with an application owner.
"""

from __future__ import annotations

import socket
import subprocess
import time

from .models import BY_NAME, Outcome, ProbeResult, ProtocolSupport
from . import openssl as ossl

# Shaped after a current Chrome ClientHello: hybrid first, classical fallbacks.
REALISTIC_GROUP_LIST = ["X25519MLKEM768", "X25519", "secp256r1", "secp384r1"]

def _invoke(info: ossl.OpenSSLInfo, host: str, port: int, sni: str | None,
            extra: list[str], timeout: float,
            trace: bool = False) -> tuple[str, int, bool]:
    """Run s_client once. Returns (combined_output, returncode, timed_out).

    stdin is closed immediately so s_client sends close_notify and exits
    instead of waiting for application data.
    """
    argv = [info.path, "s_client", "-connect", f"{host}:{port}"]
    if sni:
        argv += ["-servername", sni]
    argv += extra
    if trace and info.supports_trace:
        argv.append("-trace")

    try:
        proc = ossl._run(argv, timeout=timeout, stdin_data=b"")
    except subprocess.TimeoutExpired as exc:
        partial = b""
        for stream in (exc.stdout, exc.stderr):
            if stream:
                partial += stream
        return partial.decode(errors="replace"), -1, True
    except OSError as exc:
        return f"{exc}", -1, False

    text = (proc.stdout + proc.stderr).decode(errors="replace")
    return text, proc.returncode, False


def _result_from_output(group: str, text: str, returncode: int,
                        timed_out: bool, elapsed_ms: int) -> ProbeResult:
    if timed_out:
        return ProbeResult(
            group=group,
            outcome=Outcome.TIMEOUT.value,
            detail="no response before timeout; consistent with a silent drop",
            duration_ms=elapsed_ms,
        )

    if ossl.handshake_succeeded(text):
        version, cipher = ossl.parse_cipher_and_version(text)
        return ProbeResult(
            group=group,
            outcome=Outcome.SUPPORTED.value,
            negotiated_group=ossl.parse_negotiated_group(text),
            cipher=cipher,
            tls_version=version,
            bytes_written=ossl.parse_bytes_written(text),
            duration_ms=elapsed_ms,
        )

    outcome, alert, detail = ossl.classify_failure(text, returncode)
    return ProbeResult(
        group=group,
        outcome=outcome,
        alert=alert,
        detail=detail,
        duration_ms=elapsed_ms,
    )


def probe_group_detailed(info: ossl.OpenSSLInfo, host: str, port: int,
                         sni: str | None, group: str,
                         timeout: float = 12.0) -> tuple[ProbeResult, str]:
    """As probe_group, but also returns the raw s_client output.

    Phase 1 needs the raw text to fingerprint the peer certificate, which
    identifies *which* pool member answered. Doing it from output we already
    have costs no extra handshake.
    """
    if group not in info.groups:
        return ProbeResult(
            group=group,
            outcome=Outcome.CLIENT_UNSUPPORTED.value,
            detail=f"{info.version_string} cannot offer this group",
        ), ""
    start = time.monotonic()
    text, rc, timed_out = _invoke(
        info, host, port, sni, ["-tls1_3", "-groups", group], timeout)
    elapsed = int((time.monotonic() - start) * 1000)
    return _result_from_output(group, text, rc, timed_out, elapsed), text


def probe_default_detailed(info: ossl.OpenSSLInfo, host: str, port: int,
                           sni: str | None,
                           timeout: float = 12.0) -> tuple[ProbeResult, str]:
    start = time.monotonic()
    text, rc, timed_out = _invoke(info, host, port, sni, [], timeout)
    elapsed = int((time.monotonic() - start) * 1000)
    return _result_from_output("__default__", text, rc, timed_out, elapsed), text


def probe_realistic_detailed(info: ossl.OpenSSLInfo, host: str, port: int,
                             sni: str | None, timeout: float = 12.0,
                             trace: bool = False) -> tuple[ProbeResult, str]:
    offered = [g for g in REALISTIC_GROUP_LIST if g in info.groups] or ["X25519"]
    start = time.monotonic()
    text, rc, timed_out = _invoke(
        info, host, port, sni,
        ["-tls1_3", "-groups", ":".join(offered)], timeout, trace=trace)
    elapsed = int((time.monotonic() - start) * 1000)
    return _result_from_output("__realistic__", text, rc, timed_out, elapsed), text


def probe_group(info: ossl.OpenSSLInfo, host: str, port: int, sni: str | None,
                group: str, timeout: float = 12.0) -> ProbeResult:
    """Offer exactly one group and see whether the server can use it."""
    if group not in info.groups:
        return ProbeResult(
            group=group,
            outcome=Outcome.CLIENT_UNSUPPORTED.value,
            detail=f"{info.version_string} cannot offer this group",
        )
    start = time.monotonic()
    text, rc, timed_out = _invoke(
        info, host, port, sni,
        ["-tls1_3", "-groups", group], timeout)
    elapsed = int((time.monotonic() - start) * 1000)
    return _result_from_output(group, text, rc, timed_out, elapsed)


def probe_default(info: ossl.OpenSSLInfo, host: str, port: int,
                  sni: str | None, timeout: float = 12.0) -> ProbeResult:
    """Let the client use its own defaults — hybrid-first on 3.5."""
    start = time.monotonic()
    text, rc, timed_out = _invoke(info, host, port, sni, [], timeout)
    elapsed = int((time.monotonic() - start) * 1000)
    return _result_from_output("__default__", text, rc, timed_out, elapsed)


def probe_realistic(info: ossl.OpenSSLInfo, host: str, port: int,
                    sni: str | None, timeout: float = 12.0,
                    trace: bool = False) -> tuple[ProbeResult, bool | None]:
    """Browser-shaped group list. Second return value is HRR observed, or None
    if the client cannot trace and the answer is unknown."""
    offered = [g for g in REALISTIC_GROUP_LIST if g in info.groups]
    if not offered:
        offered = ["X25519"]
    start = time.monotonic()
    text, rc, timed_out = _invoke(
        info, host, port, sni,
        ["-tls1_3", "-groups", ":".join(offered)], timeout, trace=trace)
    elapsed = int((time.monotonic() - start) * 1000)
    result = _result_from_output("__realistic__", text, rc, timed_out, elapsed)
    hrr = ossl.saw_hello_retry_request(text) if (trace and info.supports_trace) else None
    return result, hrr


_PROTO_FLAGS = {
    "tls1_3": ["-tls1_3"],
    "tls1_2": ["-tls1_2"],
    # Legacy versions need the security level dropped or the local client
    # refuses before touching the network — which would look like a server
    # result and would be wrong.
    "tls1_1": ["-tls1_1", "-cipher", "DEFAULT@SECLEVEL=0"],
    "tls1_0": ["-tls1", "-cipher", "DEFAULT@SECLEVEL=0"],
}


def probe_protocols(info: ossl.OpenSSLInfo, host: str, port: int,
                    sni: str | None, include_legacy: bool = True,
                    timeout: float = 10.0) -> ProtocolSupport:
    support = ProtocolSupport()
    for name, flags in _PROTO_FLAGS.items():
        if not include_legacy and name in ("tls1_0", "tls1_1"):
            continue
        text, rc, timed_out = _invoke(info, host, port, sni, flags, timeout)
        if timed_out:
            setattr(support, name, None)
            support.notes.append(f"{name}: timed out, treated as unknown")
            continue
        if ossl.handshake_succeeded(text):
            setattr(support, name, True)
            continue
        outcome, _alert, detail = ossl.classify_failure(text, rc)
        if outcome == Outcome.CLIENT_UNSUPPORTED.value or "no protocols available" in text.lower():
            setattr(support, name, None)
            support.notes.append(
                f"{name}: local client cannot offer it, result unknown")
        else:
            setattr(support, name, False)
    return support


def resolve(host: str) -> str | None:
    """Record which address we actually measured.

    Anycast and global load balancers (Front Door, CDNs) mean two runs can land
    on different POPs with different TLS stacks. Capturing the IP makes an
    otherwise baffling posture flip explainable.
    """
    try:
        infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
    except socket.gaierror:
        return None
    for family in (socket.AF_INET, socket.AF_INET6):
        for entry in infos:
            if entry[0] == family:
                return entry[4][0]
    return infos[0][4][0] if infos else None
