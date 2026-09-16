"""Phase 1 orchestration: scan a service, produce evidence, assess topology.

Note what this module does *not* do: it emits no score and no grade. Under the
four-phase model, posture and risk are Phase 4 — they need the path model from
Phase 2 and the configuration facts from Phase 3 before a number means
anything. Grading a VIP in Phase 1 would be scoring a device whose role in the
path has not been established yet. scoring.py is still in the tree and still
works; it belongs to Phase 4.

A pass is one full sweep of an address: the default-client probe, the
browser-shaped probe, then one probe per group. Peer identity is captured on
every probe, so pool discovery falls out of the sweep rather than needing its
own connections.
"""

from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from datetime import datetime, timezone

from . import openssl as ossl
from . import probes
from .evidence import (
    EndpointEvidence, Observation, PeerIdentity, coverage_note, leaf_fingerprint,
)
from .inventory import Endpoint, Service
from .models import GROUP_CATALOG, LEGACY_HYBRID_ALIASES
from .topology import TopologyAssessment, assess


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _identity_from(text: str) -> PeerIdentity | None:
    fingerprint = leaf_fingerprint(text)
    if not fingerprint:
        return None
    fields = ossl.parse_chain(text)
    return PeerIdentity(
        cert_fingerprint=fingerprint,
        subject=fields.get("subject"),
        issuer=fields.get("issuer"),
        not_after=fields.get("not_after"),
        key_algorithm=fields.get("key_algorithm"),
        key_bits=fields.get("key_bits"),
        signature_algorithm=fields.get("signature_algorithm"),
        chain_length=fields.get("chain_length"),
    )


@dataclass
class ServiceResult:
    service: str
    sni: str | None = None
    declared_frontend_type: str = "unknown"
    declared_tls_mode: str = "unknown"
    data_classification: str = "unknown"
    sensitivity_horizon: str = "unknown"
    frontend: EndpointEvidence | None = None
    backends: list[EndpointEvidence] = field(default_factory=list)
    topology: TopologyAssessment = field(default_factory=TopologyAssessment)
    coverage_notes: list[str] = field(default_factory=list)
    duration_ms: int = 0


class ServiceScanner:
    def __init__(self, info: ossl.OpenSSLInfo, *, timeout: float = 12.0,
                 concurrency: int = 4, include_draft_groups: bool = False,
                 trace: bool = False, progress=None):
        self.info = info
        self.timeout = timeout
        self.concurrency = max(1, concurrency)
        self.include_draft_groups = include_draft_groups
        self.trace = trace
        self.progress = progress or (lambda msg: None)

    def groups_to_probe(self) -> list[str]:
        catalog = list(GROUP_CATALOG)
        if self.include_draft_groups:
            catalog += list(LEGACY_HYBRID_ALIASES)
        return [g.name for g in catalog if g.name in self.info.groups]

    # -- one address -------------------------------------------------------

    def scan_endpoint(self, endpoint: Endpoint, sni: str | None) -> EndpointEvidence:
        effective_sni = endpoint.sni or sni
        evidence = EndpointEvidence(
            endpoint=endpoint.address, role=endpoint.role,
            declared_label=endpoint.label, passes=endpoint.repeat)
        evidence.resolved_ip = probes.resolve(endpoint.host)
        if evidence.resolved_ip is None:
            evidence.observations.append(Observation(
                endpoint=endpoint.address, role=endpoint.role, pass_index=0,
                group_offered="__resolve__", outcome="dns_failed",
                observed_at=_now(), detail="name did not resolve"))
            return evidence

        groups = self.groups_to_probe()
        for index in range(endpoint.repeat):
            self._one_pass(evidence, endpoint, effective_sni, index, groups)
        return evidence

    def _one_pass(self, evidence: EndpointEvidence, endpoint: Endpoint,
                  sni: str | None, index: int, groups: list[str]) -> None:
        def record(probe, text: str) -> None:
            evidence.observations.append(Observation(
                endpoint=endpoint.address,
                role=endpoint.role,
                pass_index=index,
                group_offered=probe.group,
                outcome=probe.outcome,
                observed_at=_now(),
                negotiated_group=probe.negotiated_group,
                cipher=probe.cipher,
                tls_version=probe.tls_version,
                alert=probe.alert,
                detail=probe.detail,
                bytes_written=probe.bytes_written,
                peer=_identity_from(text) if text else None,
                duration_ms=probe.duration_ms,
            ))

        probe, text = probes.probe_default_detailed(
            self.info, endpoint.host, endpoint.port, sni, self.timeout)
        record(probe, text)

        probe, text = probes.probe_realistic_detailed(
            self.info, endpoint.host, endpoint.port, sni, self.timeout,
            trace=self.trace)
        record(probe, text)

        # Probes within one address stay serial: a burst of parallel
        # handshakes into a VIP is a good way to trip rate limiting and then
        # record the throttle as a cryptographic result.
        for group in groups:
            probe, text = probes.probe_group_detailed(
                self.info, endpoint.host, endpoint.port, sni, group,
                self.timeout)
            record(probe, text)

    # -- one service -------------------------------------------------------

    def scan_service(self, service: Service) -> ServiceResult:
        started = time.monotonic()
        result = ServiceResult(
            service=service.name,
            sni=service.sni,
            declared_frontend_type=(service.frontend.type.value
                                    if service.frontend else "none"),
            declared_tls_mode=(service.frontend.declared_tls_mode.value
                               if service.frontend else "unknown"),
            data_classification=service.data_classification.value,
            sensitivity_horizon=service.sensitivity_horizon.value,
        )

        if service.frontend:
            result.frontend = self.scan_endpoint(
                service.frontend.endpoint, service.sni)
            self.progress(
                f"{service.name}: frontend {service.frontend.endpoint.address} "
                f"-> {result.frontend.distinct_peer_count()} peer identity(ies)")

        for backend in service.backends:
            evidence = self.scan_endpoint(backend, service.sni)
            result.backends.append(evidence)
            self.progress(
                f"{service.name}: backend {backend.address} "
                f"{'answered TLS' if evidence.reachable() else 'no TLS'}")

        result.topology = assess(service, result.frontend, result.backends)

        for evidence in ([result.frontend] if result.frontend else []) + result.backends:
            note = coverage_note(evidence.passes, evidence.distinct_peer_count())
            if note:
                result.coverage_notes.append(f"{evidence.endpoint}: {note}")

        result.duration_ms = int((time.monotonic() - started) * 1000)
        return result

    # -- many services -----------------------------------------------------

    def scan_all(self, services: list[Service]) -> list[ServiceResult]:
        results: dict[str, ServiceResult] = {}
        with ThreadPoolExecutor(max_workers=self.concurrency) as pool:
            futures = {pool.submit(self.scan_service, svc): svc.name
                       for svc in services}
            for future in as_completed(futures):
                name = futures[future]
                try:
                    results[name] = future.result()
                except Exception as exc:
                    failed = ServiceResult(service=name)
                    failed.topology.reasoning.append(f"scan failed: {exc}")
                    results[name] = failed
                    self.progress(f"{name}: scan failed: {exc}")
        return [results[svc.name] for svc in services if svc.name in results]
