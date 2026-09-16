"""Turning probe results into a score, a grade, and actionable findings.

Weighting rationale. Key exchange dominates because it is the only part of TLS
with a retroactive exposure: traffic captured today can be decrypted once a
cryptographically relevant quantum computer exists, so a session negotiated
with classical-only KEX is a liability for as long as its contents stay
sensitive. Certificate signatures do not have that property — an attacker who
can forge a signature in 2035 gains nothing against a handshake from 2026, so
signature agility is scheduling, not triage. The scoring reflects that, and
the report says so rather than quietly burying it in the numbers.
"""

from __future__ import annotations

from datetime import datetime, timezone

from .models import (
    Finding, GroupKind, TargetResult, is_quantum_resistant, kind_of,
)

GRADE_BANDS = ((85, "A"), (70, "B"), (50, "C"), (30, "D"), (0, "F"))

# Component ceilings. They sum to 100.
MAX_KEX = 60
MAX_PROTOCOL = 20
MAX_INTEROP = 10
MAX_CERT = 10


def _grade(score: int) -> str:
    for threshold, letter in GRADE_BANDS:
        if score >= threshold:
            return letter
    return "F"


def _parse_not_after(value: str | None) -> datetime | None:
    if not value:
        return None
    for fmt in ("%b %d %H:%M:%S %Y %Z", "%b %d %H:%M:%S %Y GMT"):
        try:
            parsed = datetime.strptime(value.strip(), fmt)
            return parsed.replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    return None


def score_target(result: TargetResult) -> TargetResult:
    findings: list[Finding] = []

    if not result.reachable:
        result.score = 0
        result.grade = "F"
        result.findings = [Finding(
            "UNREACHABLE", "high",
            "No TLS handshake completed with any group; posture is unknown, "
            "not good.")]
        return result

    # ---- Key exchange (0-60) --------------------------------------------
    kex = 0
    negotiated = result.default_negotiated_group
    if result.hybrid_preferred:
        kex = MAX_KEX
        findings.append(Finding(
            "PQ_HYBRID_DEFAULT", "info",
            f"A current client negotiates {negotiated} without asking. "
            "Harvest-now-decrypt-later exposure on this endpoint is closed."))
    elif result.hybrid_supported:
        kex = 40
        supported_hybrids = [
            g for g in result.supported_groups
            if kind_of(g) == GroupKind.HYBRID]
        findings.append(Finding(
            "PQ_HYBRID_NOT_PREFERRED", "medium",
            f"Hybrid KEX is supported ({', '.join(supported_hybrids)}) but a "
            f"realistic client still lands on {negotiated}. The capability is "
            "deployed; the group priority order is not. This is usually a "
            "one-line configuration change, not a migration."))
    elif result.protocols.tls1_3:
        kex = 10
        findings.append(Finding(
            "NO_PQ_KEX", "high",
            "TLS 1.3 is available but no post-quantum group is. Every session "
            "here is recordable today and decryptable later."))
    else:
        kex = 0
        findings.append(Finding(
            "NO_TLS13", "high",
            "No TLS 1.3. Post-quantum key exchange is not reachable at all — "
            "hybrid groups exist only in the TLS 1.3 handshake."))

    if any(kind_of(g) == GroupKind.PURE_PQ for g in result.supported_groups):
        pure = [g for g in result.supported_groups
                if kind_of(g) == GroupKind.PURE_PQ]
        findings.append(Finding(
            "PURE_PQ_OFFERED", "low",
            f"Standalone ML-KEM is accepted ({', '.join(pure)}). This drops "
            "the classical hedge, so any future break in ML-KEM itself has no "
            "fallback. Prefer the hybrid groups unless something specifically "
            "requires otherwise."))

    # ---- Protocol hygiene (0-20) ----------------------------------------
    protocol = 0
    if result.protocols.tls1_3:
        protocol += 10
    if result.protocols.tls1_2 is False:
        protocol += 5
    elif result.protocols.tls1_2:
        findings.append(Finding(
            "TLS12_ENABLED", "low",
            "TLS 1.2 is still accepted. It cannot carry a hybrid group, so any "
            "client that falls back to it is unprotected regardless of the "
            "TLS 1.3 configuration."))
    if result.protocols.tls1_1 or result.protocols.tls1_0:
        legacy = [n for n, v in (("TLS 1.0", result.protocols.tls1_0),
                                 ("TLS 1.1", result.protocols.tls1_1)) if v]
        findings.append(Finding(
            "LEGACY_TLS", "high",
            f"{' and '.join(legacy)} still accepted."))
    elif result.protocols.tls1_1 is False and result.protocols.tls1_0 is False:
        protocol += 5

    # ---- Interop health (0-10) ------------------------------------------
    interop = MAX_INTEROP
    if result.large_clienthello_suspected:
        interop = 0
        findings.append(Finding(
            "LARGE_CLIENTHELLO_INTOLERANCE", "high",
            "Small ClientHellos succeed but ones carrying an ML-KEM key share "
            "die with no TLS alert. That is a path problem, not a server "
            "capability gap — something between here and the endpoint cannot "
            "handle a ClientHello split across TCP segments. Enabling hybrid "
            "KEX on the server will not fix it and may break existing "
            "clients; find the middlebox first."))

    # ---- Certificate hygiene (0-10) -------------------------------------
    cert_points = 0
    cert = result.certificate
    not_after = _parse_not_after(cert.not_after)
    if not_after:
        days = (not_after - datetime.now(timezone.utc)).days
        cert.days_remaining = days
        if days < 0:
            findings.append(Finding(
                "CERT_EXPIRED", "high", "Leaf certificate has expired."))
        elif days < 30:
            findings.append(Finding(
                "CERT_EXPIRING", "medium",
                f"Leaf certificate expires in {days} days."))
        else:
            cert_points += 5
    if cert.verify_ok is False:
        findings.append(Finding(
            "CERT_VERIFY_FAILED", "medium",
            f"Chain verification failed: {cert.verify_error}. Scored "
            "separately from posture, but it will break clients before any "
            "quantum concern does."))

    weak_key = False
    if cert.key_algorithm and cert.key_bits:
        alg = cert.key_algorithm.lower()
        if "rsa" in alg and cert.key_bits < 2048:
            weak_key = True
        if ("ec" in alg or "id-ecpublickey" in alg) and cert.key_bits < 256:
            weak_key = True
    if weak_key:
        findings.append(Finding(
            "WEAK_CERT_KEY", "high",
            f"Leaf key is {cert.key_algorithm} {cert.key_bits}-bit."))
    else:
        cert_points += 5

    if cert.signature_algorithm:
        findings.append(Finding(
            "CERT_SIG_CLASSICAL", "info",
            f"Certificate signature is {cert.signature_algorithm}. Classical "
            "signatures are expected in 2026 and are not retroactively "
            "exploitable — do not treat this as urgent alongside the key "
            "exchange findings."))

    score = min(kex, MAX_KEX) + min(protocol, MAX_PROTOCOL) \
        + min(interop, MAX_INTEROP) + min(cert_points, MAX_CERT)

    result.score = score
    result.grade = _grade(score)
    result.findings = findings
    return result


def score_breakdown(result: TargetResult) -> dict[str, int]:
    """Component view, for the Phase 3 gate to diff dimension by dimension."""
    return {
        "key_exchange": MAX_KEX if result.hybrid_preferred
        else 40 if result.hybrid_supported
        else 10 if result.protocols.tls1_3 else 0,
        "protocol": MAX_PROTOCOL,
        "interop": 0 if result.large_clienthello_suspected else MAX_INTEROP,
        "certificate": MAX_CERT,
    }
