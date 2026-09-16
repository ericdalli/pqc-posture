"""Topology assessment — the one place Phase 1 is allowed to infer.

This is deliberately a separate layer from evidence.py. Every value here is a
pure function of stored observations, which means it can be recomputed,
overridden, or thrown away entirely when Phase 2 brings better information.
Nothing in this module ever writes back into the evidence record. That is what
keeps "Phase 1 makes no assumptions" true at the layer that matters: the
evidence is assumption-free, and the assessment is a clearly labelled opinion
sitting on top of it.

A limit worth stating plainly rather than burying in a confidence score:
**terminate and reencrypt are not distinguishable from outside.** Both present
the frontend's own certificate to us. The difference between them is what the
frontend does on the leg to the backend, and that leg is not observable from a
client vantage point. Probing a backend directly and finding it speaks TLS
shows only that re-encryption is *possible* — the frontend may still be
talking cleartext to a port that also happens to accept TLS. Resolving that
needs configuration, which is Phase 3.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .evidence import EndpointEvidence
from .inventory import FrontendType, Service, TlsMode


class Confidence:
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INDETERMINATE = "indeterminate"


@dataclass
class TopologyAssessment:
    declared: str = TlsMode.UNKNOWN.value
    observed: str = "indeterminate"
    confidence: str = Confidence.INDETERMINATE
    reasoning: list[str] = field(default_factory=list)
    conflicts: list[str] = field(default_factory=list)
    signals: dict = field(default_factory=dict)


def assess(service: Service, frontend_ev: EndpointEvidence | None,
           backend_evs: list[EndpointEvidence]) -> TopologyAssessment:
    declared = (service.frontend.declared_tls_mode.value
                if service.frontend else TlsMode.UNKNOWN.value)
    result = TopologyAssessment(declared=declared)

    if frontend_ev is None or not frontend_ev.reachable():
        result.observed = "not_observed"
        result.reasoning.append(
            "no completed handshake with the frontend; nothing was observed "
            "to assess")
        return result

    fe_peers = frontend_ev.peers()
    fe_prints = set(fe_peers)
    fe_groups = frontend_ev.groups_observed_supported()

    reachable_backends = [ev for ev in backend_evs if ev.reachable()]
    result.signals = {
        "frontend_peer_identities": sorted(fe_prints),
        "frontend_groups_observed_supported": sorted(fe_groups),
        "backends_declared": len(backend_evs),
        "backends_answering_tls": len(reachable_backends),
    }

    if not backend_evs:
        result.observed = "indeterminate"
        result.confidence = Confidence.INDETERMINATE
        result.reasoning.append(
            "no backends declared. From a single vantage point in front of "
            "the VIP, a terminating proxy and a passthrough VIP to one origin "
            "are indistinguishable — both just present a certificate.")
        _note_frontend_type_conflict(service, frontend_ev, result)
        _note_inconsistency(frontend_ev, result, "frontend")
        return result

    if not reachable_backends:
        result.observed = "likely_tls_termination"
        result.confidence = Confidence.LOW
        result.reasoning.append(
            f"{len(backend_evs)} backend(s) declared, none completed a TLS "
            "handshake on the probed port. Consistent with the frontend "
            "terminating and speaking cleartext to the backends — but equally "
            "consistent with the backends being firewalled from this scanner, "
            "which is why confidence is low rather than high.")
        _resolve_conflict(declared, result)
        return result

    be_prints: set[str] = set()
    be_groups: set[str] = set()
    for ev in reachable_backends:
        be_prints |= set(ev.peers())
        be_groups |= ev.groups_observed_supported()

    shared_cert = bool(fe_prints & be_prints)
    result.signals["backend_peer_identities"] = sorted(be_prints)
    result.signals["backend_groups_observed_supported"] = sorted(be_groups)
    result.signals["certificate_shared_frontend_backend"] = shared_cert

    # Strongest available signal, and the only one that can reach high
    # confidence: two TLS stacks that accept different group sets cannot be
    # the same TLS stack. A passthrough VIP forwards the handshake untouched,
    # so the group set observed at the VIP must match the member's exactly.
    group_divergence = bool(fe_groups and be_groups and fe_groups != be_groups)
    result.signals["group_support_diverges"] = group_divergence

    if group_divergence:
        only_fe = sorted(fe_groups - be_groups)
        only_be = sorted(be_groups - fe_groups)
        result.reasoning.append(
            "group support observed at the frontend differs from the "
            f"backends (frontend-only: {only_fe or 'none'}; backend-only: "
            f"{only_be or 'none'}). A passthrough VIP forwards the handshake "
            "untouched, so this rules passthrough out.")

    if shared_cert and not group_divergence:
        result.observed = "likely_passthrough"
        result.confidence = Confidence.MEDIUM
        result.reasoning.append(
            "the frontend presents the same leaf certificate as a backend, "
            "and the observed group support matches.")
        result.reasoning.append(
            "capped at medium: a terminating proxy configured with the same "
            "imported certificate and a similar TLS profile produces exactly "
            "this evidence. Certificate identity alone does not prove the "
            "handshake was forwarded.")
    elif shared_cert and group_divergence:
        result.observed = "likely_tls_termination"
        result.confidence = Confidence.MEDIUM
        result.reasoning.append(
            "same certificate as a backend, but divergent group support. That "
            "combination points at a terminating device using an imported "
            "copy of the backend certificate — a common F5 pattern, and one "
            "that is routinely mistaken for passthrough.")
    else:
        # Different certificate. Termination is established; which flavour is
        # not, and cannot be from here.
        result.observed = "likely_tls_termination"
        result.confidence = (Confidence.HIGH if group_divergence
                             else Confidence.MEDIUM)
        result.reasoning.append(
            "the frontend presents a different leaf certificate than any "
            "probed backend, so the TLS session is being terminated at the "
            "frontend.")
        result.reasoning.append(
            f"{len(reachable_backends)} backend(s) answer TLS themselves, so "
            "re-encryption is possible — but whether the frontend actually "
            "re-encrypts to them, or speaks cleartext to a port that happens "
            "to also accept TLS, is not observable from here. Distinguishing "
            "terminate from reencrypt needs configuration (Phase 3).")

    _note_frontend_type_conflict(service, frontend_ev, result)
    _note_inconsistency(frontend_ev, result, "frontend")
    for ev in reachable_backends:
        _note_inconsistency(ev, result, ev.endpoint)
    _resolve_conflict(declared, result)
    return result


def _resolve_conflict(declared: str, result: TopologyAssessment) -> None:
    """Declared versus observed. A mismatch is a finding, not an error."""
    if declared == TlsMode.UNKNOWN.value:
        return
    observed = result.observed
    contradicts = (
        (declared == TlsMode.PASSTHROUGH.value
         and observed == "likely_tls_termination"),
        (declared in (TlsMode.TERMINATE.value, TlsMode.REENCRYPT.value)
         and observed == "likely_passthrough"),
    )
    if any(contradicts):
        result.conflicts.append(
            f"declared tls_mode is '{declared}' but the observation points at "
            f"'{observed}'. Either the declaration is stale, or the device "
            f"answering this address is not the one documented. Worth "
            f"resolving before the declaration is relied on anywhere else.")
    elif declared == TlsMode.PASSTHROUGH.value and observed == "likely_passthrough":
        result.reasoning.append("declaration and observation agree.")


def _note_frontend_type_conflict(service: Service, frontend_ev: EndpointEvidence,
                                 result: TopologyAssessment) -> None:
    """Some declared frontend types cannot do what was observed."""
    if not service.frontend:
        return
    ftype = service.frontend.type
    # A layer-4 load balancer does not own a certificate. If one was declared
    # and the observation shows termination, the declaration is wrong or the
    # address belongs to something else.
    layer4 = {FrontendType.AWS_NLB}
    if ftype in layer4 and result.observed == "likely_tls_termination":
        result.conflicts.append(
            f"declared frontend type '{ftype.value}' operates at layer 4 and "
            "does not terminate TLS, but termination was observed at this "
            "address.")
    if ftype is FrontendType.NONE and frontend_ev.distinct_peer_count() > 1:
        result.conflicts.append(
            "frontend declared as 'none' (direct to origin), but more than "
            "one peer identity answered this address — something is "
            "distributing connections.")


def _note_inconsistency(ev: EndpointEvidence, result: TopologyAssessment,
                        where: str) -> None:
    divergent = ev.inconsistencies()
    if divergent:
        result.conflicts.append(
            f"{where}: the same group produced different outcomes across "
            f"passes ({', '.join(divergent)}). More than one TLS "
            f"configuration is live behind this address — a partial rollout "
            f"or a drifted pool member. Any single-pass result for this "
            f"address is unreliable.")
    peers = ev.distinct_peer_count()
    if peers > 1:
        result.signals.setdefault("distinct_peers", {})[where] = peers
