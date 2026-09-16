"""Rendering scan reports."""

from __future__ import annotations

import json

from .models import GroupKind, ScanReport, TargetResult, VOLATILE_FIELDS, kind_of

SEVERITY_ORDER = {"high": 0, "medium": 1, "low": 2, "info": 3}
SEVERITY_MARK = {"high": "!!", "medium": " !", "low": "  ", "info": "  "}


def to_json(report: ScanReport, indent: int = 2) -> str:
    payload = report.to_dict()
    payload["_volatile_fields"] = list(VOLATILE_FIELDS)
    return json.dumps(payload, indent=indent, sort_keys=True, default=str)


def _group_line(result: TargetResult) -> str:
    if not result.supported_groups:
        return "none"
    buckets: dict[str, list[str]] = {}
    for group in result.supported_groups:
        kind = kind_of(group)
        buckets.setdefault(kind.value if kind else "other", []).append(group)
    parts = []
    for key in ("hybrid", "pure_pq", "classical_ec", "classical_ff", "other"):
        if key in buckets:
            parts.append(f"{key}: {', '.join(buckets[key])}")
    return "; ".join(parts)


def render_target(result: TargetResult, verbose: bool = False) -> str:
    lines: list[str] = []
    head = f"{result.label}  [{result.grade}] {result.score}/100"
    lines.append(head)
    lines.append("-" * len(head))

    if result.resolved_ip:
        lines.append(f"  measured against : {result.resolved_ip}")
    if not result.reachable:
        lines.append("  no TLS handshake completed")
        return "\n".join(lines)

    negotiated = result.preferred_group_realistic or result.default_negotiated_group
    pq = kind_of(negotiated or "") in (GroupKind.HYBRID, GroupKind.PURE_PQ)
    lines.append(f"  negotiated group : {negotiated or 'unknown'}"
                 f"{'  (post-quantum)' if pq else '  (classical)'}")
    if result.default_negotiated_group and \
            result.default_negotiated_group != negotiated:
        lines.append(f"  default client   : {result.default_negotiated_group}")

    proto = result.protocols
    enabled = [name for name, flag in (
        ("1.3", proto.tls1_3), ("1.2", proto.tls1_2),
        ("1.1", proto.tls1_1), ("1.0", proto.tls1_0)) if flag]
    lines.append(f"  TLS versions     : {', '.join(enabled) or 'none detected'}")
    lines.append(f"  groups accepted  : {_group_line(result)}")

    cert = result.certificate
    if cert.subject:
        expiry = (f", {cert.days_remaining}d left"
                  if cert.days_remaining is not None else "")
        lines.append(
            f"  certificate      : {cert.key_algorithm or '?'} "
            f"{cert.key_bits or '?'}-bit, {cert.signature_algorithm or '?'}"
            f"{expiry}")

    if result.findings:
        lines.append("  findings:")
        ordered = sorted(result.findings,
                         key=lambda f: SEVERITY_ORDER.get(f.severity, 9))
        for finding in ordered:
            if not verbose and finding.severity == "info":
                continue
            mark = SEVERITY_MARK.get(finding.severity, "  ")
            lines.append(f"   {mark} [{finding.code}] {finding.message}")

    if verbose:
        lines.append("  probes:")
        for probe in result.probes:
            detail = f" — {probe.detail}" if probe.detail else ""
            lines.append(
                f"      {probe.group:<24} {probe.outcome}"
                f"{' -> ' + probe.negotiated_group if probe.negotiated_group else ''}"
                f"{detail}")
    return "\n".join(lines)


def render(report: ScanReport, verbose: bool = False) -> str:
    blocks = [
        f"pqc-posture {report.tool_version}",
        f"client: {report.openssl_version}  ({report.openssl_path})",
        f"hybrid groups offerable by this client: "
        f"{', '.join(g for g in report.client_groups_available if kind_of(g) == GroupKind.HYBRID) or 'none'}",
        "",
    ]
    for result in report.targets:
        blocks.append(render_target(result, verbose=verbose))
        blocks.append("")

    graded = [t for t in report.targets]
    if graded:
        hybrid = sum(1 for t in graded if t.hybrid_preferred)
        capable = sum(1 for t in graded if t.hybrid_supported)
        blocks.append(
            f"summary: {hybrid}/{len(graded)} negotiate hybrid KEX by default; "
            f"{capable}/{len(graded)} support it at all")
    return "\n".join(blocks)


# --------------------------------------------------------------------------
# Phase 1 service-level rendering
# --------------------------------------------------------------------------

def _support_row(matrix: dict, peer_key: str) -> str:
    row = matrix.get(peer_key, {})
    supported = sorted(g for g, s in row.items() if s == "observed_supported")
    rejected = sorted(g for g, s in row.items() if s == "observed_rejected")
    unseen = sorted(g for g, s in row.items() if s == "not_observed")
    parts = [f"supported: {', '.join(supported) or 'none'}"]
    if rejected:
        parts.append(f"rejected: {', '.join(rejected)}")
    if unseen:
        parts.append(f"NOT OBSERVED: {', '.join(unseen)}")
    return " | ".join(parts)


def render_endpoint_evidence(ev, indent: str = "  ") -> list[str]:
    lines = [f"{indent}{ev.role}: {ev.endpoint}"
             f"{' (' + ev.resolved_ip + ')' if ev.resolved_ip and ev.resolved_ip != ev.endpoint.split(':')[0] else ''}"]
    if not ev.reachable():
        lines.append(f"{indent}  no completed handshake in "
                     f"{ev.passes} pass(es)")
        return lines
    lines.append(f"{indent}  passes: {ev.passes}   "
                 f"peer identities: {ev.distinct_peer_count()}")
    negotiated = ev.negotiated_realistic() or ev.negotiated_by_default()
    lines.append(f"{indent}  negotiated (browser-shaped): {negotiated or 'unknown'}")
    matrix = ev.support_matrix()
    for key, peer in ev.peers().items():
        lines.append(f"{indent}  peer {key}  {peer.subject or '?'}")
        lines.append(f"{indent}    {_support_row(matrix, key)}")
    # Groups with no evidence either way must stay visible. Probes that never
    # reached a peer carry no certificate, so they aggregate under an
    # unidentified key and would otherwise vanish from the rendered output --
    # silently turning "we did not find out" into "it is not supported",
    # which is the exact failure this model exists to prevent.
    best: dict = {}
    rank = {"not_observed": 0, "observed_rejected": 1, "observed_supported": 2}
    for row in matrix.values():
        for group, state in row.items():
            if group not in best or rank[state] > rank[best[group]]:
                best[group] = state
    unseen = sorted(g for g, state in best.items() if state == "not_observed")
    if unseen:
        lines.append(f"{indent}  NOT OBSERVED (no evidence either way): "
                     f"{', '.join(unseen)}")
    divergent = ev.inconsistencies()
    if divergent:
        lines.append(f"{indent}  INCONSISTENT across passes: "
                     f"{', '.join(divergent)}")
    return lines


def render_service(result) -> str:
    lines = [f"SERVICE  {result.service}   (sni: {result.sni or 'none'})",
             "=" * (9 + len(result.service))]
    classification = getattr(result, "data_classification", "unknown")
    horizon = getattr(result, "sensitivity_horizon", "unknown")
    if classification != "unknown" or horizon != "unknown":
        lines.append(f"  declared context : data={classification}, "
                     f"sensitive-for={horizon}")
    else:
        # Undeclared context is stated, not hidden. Severity for findings like
        # LEGACY_TLS and NO_PQ_KEX depends on it, and an inventory that is
        # silently all-unknown should look incomplete rather than reassuring.
        lines.append("  declared context : none (data_classification and "
                     "sensitivity_horizon not set)")
    if result.frontend:
        lines += render_endpoint_evidence(result.frontend)
    for backend in result.backends:
        lines += render_endpoint_evidence(backend)

    topo = result.topology
    lines.append("")
    lines.append("  Topology assessment:")
    lines.append(f"    Declared:   {topo.declared}"
                 f" (frontend type: {result.declared_frontend_type})")
    lines.append(f"    Observed:   {topo.observed}")
    lines.append(f"    Confidence: {topo.confidence}")
    for reason in topo.reasoning:
        lines.append(f"      - {reason}")
    for conflict in topo.conflicts:
        lines.append(f"    !! CONFLICT: {conflict}")
    for note in result.coverage_notes:
        lines.append(f"    ~  coverage: {note}")
    return "\n".join(lines)


def services_to_json(results, openssl_version: str = "",
                     client_groups=None, indent: int = 2) -> str:
    from dataclasses import asdict
    payload = {
        "schema_version": 1,
        "phase": 1,
        "phase_name": "observation",
        "openssl_version": openssl_version,
        "client_groups_available": sorted(client_groups or []),
        "_volatile_fields": [
            "observed_at", "duration_ms", "observations.*.duration_ms",
            "resolved_ip",
        ],
        "_note": (
            "evidence[] is observation-only and carries no inference. "
            "topology is a derived assessment and can be recomputed from "
            "evidence alone. Absence of an observation is not evidence of "
            "absence: see not_observed in the support matrix."
        ),
        "services": [],
    }
    for result in results:
        entry = asdict(result)
        entry["derived"] = {
            "frontend_support_matrix":
                result.frontend.support_matrix() if result.frontend else {},
            "backend_support_matrices": [
                {"endpoint": b.endpoint, "matrix": b.support_matrix()}
                for b in result.backends
            ],
        }
        payload["services"].append(entry)
    return json.dumps(payload, indent=indent, sort_keys=True, default=str)
