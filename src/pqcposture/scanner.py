"""Scan orchestration."""

from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone

from .models import (
    CertificateInfo, GROUP_CATALOG, GroupKind, LEGACY_HYBRID_ALIASES,
    Outcome, ScanReport, TargetResult, is_quantum_resistant, kind_of,
)
from . import openssl as ossl
from . import probes
from .scoring import score_target


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


class Scanner:
    def __init__(self, info: ossl.OpenSSLInfo, *, timeout: float = 12.0,
                 concurrency: int = 8, include_legacy_tls: bool = True,
                 include_draft_groups: bool = False, trace: bool = False,
                 progress=None):
        self.info = info
        self.timeout = timeout
        self.concurrency = max(1, concurrency)
        self.include_legacy_tls = include_legacy_tls
        self.include_draft_groups = include_draft_groups
        self.trace = trace
        self.progress = progress or (lambda msg: None)

    # -- group selection ---------------------------------------------------

    def groups_to_probe(self) -> list[str]:
        catalog = list(GROUP_CATALOG)
        if self.include_draft_groups:
            catalog += list(LEGACY_HYBRID_ALIASES)
        return [g.name for g in catalog if g.name in self.info.groups]

    # -- per-target --------------------------------------------------------

    def scan_target(self, host: str, port: int, sni: str | None = None) -> TargetResult:
        started = time.monotonic()
        result = TargetResult(host=host, port=port, sni=sni or host)
        result.resolved_ip = probes.resolve(host)

        if result.resolved_ip is None:
            result.duration_ms = int((time.monotonic() - started) * 1000)
            return score_target(result)

        # Default-client probe first: cheapest way to learn what a current
        # client gets today, and it establishes reachability.
        default_probe = probes.probe_default(
            self.info, host, port, result.sni, self.timeout)
        result.probes.append(default_probe)
        if default_probe.supported:
            result.reachable = True
            result.default_negotiated_group = default_probe.negotiated_group
            self._absorb_certificate(result, host, port)

        realistic, hrr = probes.probe_realistic(
            self.info, host, port, result.sni, self.timeout, trace=self.trace)
        result.probes.append(realistic)
        if realistic.supported:
            result.reachable = True
            result.preferred_group_realistic = realistic.negotiated_group
            if hrr is not None:
                realistic.detail = (
                    "HelloRetryRequest observed — server declined the hybrid "
                    "key share and forced a second round trip"
                    if hrr else "negotiated in one round trip, no HRR")

        # Capability probes, serialised per target. Firing a dozen concurrent
        # handshakes at one hostname is a reliable way to get rate-limited by a
        # WAF and then misreport the result as "no PQ support".
        for group in self.groups_to_probe():
            probe = probes.probe_group(
                self.info, host, port, result.sni, group, self.timeout)
            result.probes.append(probe)
            if probe.supported:
                result.reachable = True
                result.supported_groups.append(group)

        self._derive(result)
        result.duration_ms = int((time.monotonic() - started) * 1000)
        return score_target(result)

    # -- inference ---------------------------------------------------------

    def _derive(self, result: TargetResult) -> None:
        result.hybrid_supported = any(
            kind_of(g) == GroupKind.HYBRID for g in result.supported_groups)

        negotiated = (result.preferred_group_realistic
                      or result.default_negotiated_group)
        result.hybrid_preferred = bool(
            negotiated and kind_of(negotiated) == GroupKind.HYBRID)

        if result.protocols.tls1_3 is None:
            result.protocols = probes.probe_protocols(
                self.info, result.host, result.port, result.sni,
                include_legacy=self.include_legacy_tls, timeout=self.timeout)

        result.large_clienthello_suspected = self._suspect_large_ch(result)

    def _suspect_large_ch(self, result: TargetResult) -> bool:
        """Did small ClientHellos work while large ones died without an alert?

        A server that simply lacks ML-KEM answers a hybrid-only ClientHello
        with alert 40. Silence is different: it means the ClientHello never
        arrived intact, which points at the path rather than the endpoint.
        """
        by_group = {p.group: p for p in result.probes}
        small_ok = any(
            p.supported for g, p in by_group.items()
            if (spec := next((s for s in GROUP_CATALOG if s.name == g), None))
            and spec.key_share_bytes < 300)
        if not small_ok:
            return False

        silent = {Outcome.TRANSPORT_FAILED.value, Outcome.TIMEOUT.value}
        for group, probe in by_group.items():
            if group not in self.info.groups:
                # Never infer a network problem from a group this client could
                # not offer in the first place — that failure never left the
                # process.
                continue
            spec = next((s for s in GROUP_CATALOG if s.name == group), None)
            if spec and spec.key_share_bytes > 1000 and probe.outcome in silent:
                return True
        return False

    def _absorb_certificate(self, result: TargetResult, host: str,
                            port: int) -> None:
        text, rc, timed_out = probes._invoke(
            self.info, host, port, result.sni, ["-showcerts"], self.timeout)
        if timed_out:
            return
        fields = ossl.parse_chain(text)
        verify_ok, verify_error = ossl.parse_verify(text)
        result.certificate = CertificateInfo(
            subject=fields.get("subject"),
            issuer=fields.get("issuer"),
            key_algorithm=fields.get("key_algorithm"),
            key_bits=fields.get("key_bits"),
            signature_algorithm=fields.get("signature_algorithm"),
            not_before=fields.get("not_before"),
            not_after=fields.get("not_after"),
            chain_length=fields.get("chain_length"),
            verify_ok=verify_ok,
            verify_error=verify_error,
        )

    # -- batch -------------------------------------------------------------

    def scan(self, targets: list[tuple[str, int, str | None]]) -> ScanReport:
        report = ScanReport(
            openssl_version=self.info.version_string,
            openssl_path=self.info.path,
            client_groups_available=list(self.info.groups),
            started_at=_now(),
        )
        results: dict[str, TargetResult] = {}
        with ThreadPoolExecutor(max_workers=self.concurrency) as pool:
            futures = {
                pool.submit(self.scan_target, host, port, sni): f"{host}:{port}"
                for host, port, sni in targets
            }
            for future in as_completed(futures):
                label = futures[future]
                try:
                    results[label] = future.result()
                except Exception as exc:  # a crashed probe must not lose the run
                    host, _, port = label.rpartition(":")
                    failed = TargetResult(host=host, port=int(port), sni=host)
                    failed.findings = []
                    results[label] = score_target(failed)
                    self.progress(f"{label}: scan failed: {exc}")
                else:
                    self.progress(
                        f"{label}: {results[label].grade} "
                        f"({results[label].score}/100)")

        # Deterministic ordering so two reports diff cleanly in CI.
        report.targets = [results[f"{h}:{p}"] for h, p, _ in targets
                          if f"{h}:{p}" in results]
        report.finished_at = _now()
        return report
