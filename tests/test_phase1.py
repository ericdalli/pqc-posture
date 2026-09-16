"""Phase 1 tests: inventory, evidence discipline, topology inference."""

from __future__ import annotations

import pathlib
import sys

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "src"))

from pqcposture.evidence import (  # noqa: E402
    EndpointEvidence, Observation, PeerIdentity, Support, coverage_note,
    leaf_fingerprint,
)
from pqcposture.inventory import (  # noqa: E402
    FrontendType, InventoryError, Service, TlsMode, load_inventory,
)
from pqcposture.topology import Confidence, assess  # noqa: E402

FIXTURES = pathlib.Path(__file__).parent / "fixtures"


# -- inventory -------------------------------------------------------------

def test_exact_example_schema_parses():
    raw = {"service": "def.company.com",
           "vip": {"ip": "10.1.1.3", "port": 443, "tls_mode": "passthrough"},
           "backends": ["30.1.1.2", "30.1.1.3"]}
    service = load_inventory(raw)[0]
    assert service.frontend.endpoint.host == "10.1.1.3"
    assert service.frontend.declared_tls_mode is TlsMode.PASSTHROUGH
    assert [b.address for b in service.backends] == \
        ["30.1.1.2:443", "30.1.1.3:443"]


def test_declared_vip_without_type_is_unknown_not_absent():
    """The distinction inverts the topology logic, so it is pinned."""
    service = load_inventory({"service": "s", "vip": {"ip": "10.0.0.1"}})[0]
    assert service.frontend.type is FrontendType.UNKNOWN
    assert service.has_frontend is True


def test_explicit_none_means_no_frontend():
    service = load_inventory(
        {"service": "s", "frontend": {"type": "none", "ip": "origin.example"}})[0]
    assert service.has_frontend is False


def test_backends_inherit_service_name_as_sni():
    """Probing a backend IP with no SNI often returns a different vhost, and
    the resulting certificate mismatch would read as a topology signal."""
    service = load_inventory(
        {"service": "app.example.com", "backends": ["10.0.0.9"]})[0]
    assert service.backends[0].sni == "app.example.com"


def test_backend_object_form_overrides_port_and_sni():
    service = load_inventory({"service": "s", "backends": [
        {"ip": "10.0.0.9", "port": 8443, "sni": "internal.example", "label": "web01"}]})[0]
    backend = service.backends[0]
    assert (backend.port, backend.sni, backend.label) == \
        (8443, "internal.example", "web01")


@pytest.mark.parametrize("alias,expected", [
    ("bigip", FrontendType.F5), ("AppGW", FrontendType.AZURE_APP_GATEWAY),
    ("front_door", FrontendType.AZURE_FRONT_DOOR), ("nlb", FrontendType.AWS_NLB),
])
def test_frontend_type_aliases(alias, expected):
    service = load_inventory(
        {"service": "s", "vip": {"ip": "1.1.1.1", "type": alias}})[0]
    assert service.frontend.type is expected


@pytest.mark.parametrize("alias,expected", [
    ("offload", TlsMode.TERMINATE), ("bridge", TlsMode.REENCRYPT),
    ("pass", TlsMode.PASSTHROUGH), (None, TlsMode.UNKNOWN),
])
def test_tls_mode_aliases(alias, expected):
    service = load_inventory(
        {"service": "s", "vip": {"ip": "1.1.1.1", "tls_mode": alias}})[0]
    assert service.frontend.declared_tls_mode is expected


def test_bad_tls_mode_is_rejected_loudly():
    with pytest.raises(InventoryError, match="tls_mode"):
        load_inventory({"service": "s", "vip": {"ip": "1.1.1.1",
                                                "tls_mode": "sortof"}})


def test_service_with_neither_frontend_nor_backends_is_rejected():
    with pytest.raises(InventoryError, match="neither"):
        load_inventory({"service": "s"})


# -- evidence --------------------------------------------------------------

def _obs(group, outcome, peer=None, index=0, endpoint="10.0.0.1:443",
         role="frontend"):
    return Observation(endpoint=endpoint, role=role, pass_index=index,
                       group_offered=group, outcome=outcome,
                       peer=PeerIdentity(cert_fingerprint=peer) if peer else None)


def test_leaf_fingerprint_matches_openssl_sha256():
    """Pinned against `openssl x509 -fingerprint -sha256` on a real cert, so
    the value can be compared with anything else in the estate."""
    text = (FIXTURES / "leaf_with_pem.txt").read_text()
    assert leaf_fingerprint(text) == (
        "38008919092df839a1cd191f0230c783d4b67d1edda649d34f1cf781c4f04e2f")


def test_leaf_fingerprint_absent_when_no_certificate_was_returned():
    assert leaf_fingerprint("no certificate here") is None
    assert leaf_fingerprint("") is None


def test_unobserved_group_is_not_reported_as_unsupported():
    """The core Phase 1 discipline: absence of evidence is not evidence."""
    ev = EndpointEvidence(endpoint="10.0.0.1:443", role="frontend", passes=1)
    ev.observations = [
        _obs("X25519", "supported", peer="aa" * 32),
        _obs("X25519MLKEM768", "timeout", peer=None),
    ]
    states = {g: state for row in ev.support_matrix().values()
              for g, state in row.items()}
    assert states["X25519MLKEM768"] == Support.NOT_OBSERVED.value
    assert states["X25519MLKEM768"] != Support.OBSERVED_REJECTED.value


def test_explicit_rejection_is_distinct_from_not_observed():
    ev = EndpointEvidence(endpoint="10.0.0.1:443", role="frontend", passes=1)
    ev.observations = [_obs("MLKEM768", "rejected", peer="bb" * 32)]
    states = list(ev.support_matrix().values())[0]
    assert states["MLKEM768"] == Support.OBSERVED_REJECTED.value


def test_one_success_outranks_later_inconclusive_attempts():
    ev = EndpointEvidence(endpoint="10.0.0.1:443", role="frontend", passes=2)
    ev.observations = [
        _obs("X25519MLKEM768", "supported", peer="cc" * 32, index=0),
        _obs("X25519MLKEM768", "timeout", peer="cc" * 32, index=1),
    ]
    states = list(ev.support_matrix().values())[0]
    assert states["X25519MLKEM768"] == Support.OBSERVED_SUPPORTED.value


def test_divergent_outcomes_across_passes_prove_heterogeneous_pool():
    ev = EndpointEvidence(endpoint="10.1.1.3:443", role="frontend", passes=2)
    ev.observations = [
        _obs("X25519MLKEM768", "supported", peer="dd" * 32, index=0),
        _obs("X25519MLKEM768", "rejected", peer="dd" * 32, index=1),
    ]
    # Same certificate on both passes, yet different answers.
    assert ev.distinct_peer_count() == 1
    assert ev.inconsistencies() == ["X25519MLKEM768"]


def test_client_unsupported_does_not_count_as_inconsistency():
    ev = EndpointEvidence(endpoint="10.1.1.3:443", role="frontend", passes=2)
    ev.observations = [
        _obs("MLKEM768", "client_unsupported", index=0),
        _obs("MLKEM768", "supported", peer="ee" * 32, index=1),
    ]
    assert ev.inconsistencies() == []


def test_single_peer_over_many_passes_flags_persistence_ambiguity():
    note = coverage_note(passes=10, distinct_peers=1)
    assert "persistence" in note


def test_partial_coverage_is_flagged():
    note = coverage_note(passes=4, distinct_peers=3)
    assert "incomplete" in note


# -- topology --------------------------------------------------------------

def _evidence(endpoint, role, peer_prints, groups, reachable=True, passes=1):
    ev = EndpointEvidence(endpoint=endpoint, role=role, passes=passes)
    ev.resolved_ip = endpoint.split(":")[0]
    for fingerprint in peer_prints:
        for group in groups:
            ev.observations.append(Observation(
                endpoint=endpoint, role=role, pass_index=0,
                group_offered=group,
                outcome="supported" if reachable else "rejected",
                peer=PeerIdentity(cert_fingerprint=fingerprint)))
    return ev


def _service(mode="unknown", ftype="unknown", backends=1):
    raw = {"service": "s.example.com",
           "vip": {"ip": "10.1.1.3", "type": ftype, "tls_mode": mode},
           "backends": [f"30.1.1.{i}" for i in range(2, 2 + backends)]}
    return load_inventory(raw)[0]


def test_same_cert_same_groups_reads_as_passthrough_but_only_medium():
    service = _service()
    fe = _evidence("10.1.1.3:443", "frontend", ["aa" * 32], ["X25519"])
    be = _evidence("30.1.1.2:443", "backend", ["aa" * 32], ["X25519"])
    result = assess(service, fe, [be])
    assert result.observed == "likely_passthrough"
    assert result.confidence == Confidence.MEDIUM
    assert any("imported certificate" in r for r in result.reasoning)


def test_different_cert_and_divergent_groups_reaches_high_confidence():
    service = _service()
    fe = _evidence("10.1.1.3:443", "frontend", ["aa" * 32],
                   ["X25519", "X25519MLKEM768"])
    be = _evidence("30.1.1.2:443", "backend", ["bb" * 32], ["X25519"])
    result = assess(service, fe, [be])
    assert result.observed == "likely_tls_termination"
    assert result.confidence == Confidence.HIGH


def test_same_cert_but_divergent_groups_still_rules_out_passthrough():
    """The F5 imported-cert case that gets mistaken for passthrough."""
    service = _service()
    fe = _evidence("10.1.1.3:443", "frontend", ["aa" * 32],
                   ["X25519", "X25519MLKEM768"])
    be = _evidence("30.1.1.2:443", "backend", ["aa" * 32], ["X25519"])
    result = assess(service, fe, [be])
    assert result.observed == "likely_tls_termination"


def test_terminate_and_reencrypt_are_never_separated():
    service = _service()
    fe = _evidence("10.1.1.3:443", "frontend", ["aa" * 32], ["X25519"])
    be = _evidence("30.1.1.2:443", "backend", ["bb" * 32], ["X25519"])
    result = assess(service, fe, [be])
    assert result.observed != "likely_reencrypt"
    assert any("not observable from here" in r for r in result.reasoning)


def test_declared_passthrough_contradicted_by_observation_is_a_conflict():
    service = _service(mode="passthrough")
    fe = _evidence("10.1.1.3:443", "frontend", ["aa" * 32], ["X25519"])
    be = _evidence("30.1.1.2:443", "backend", ["bb" * 32], ["X25519"])
    result = assess(service, fe, [be])
    assert result.declared == "passthrough"
    assert any("stale" in c for c in result.conflicts)


def test_no_backends_is_indeterminate_not_a_guess():
    service = load_inventory(
        {"service": "s", "vip": {"ip": "10.1.1.3"}, "backends": []})[0]
    fe = _evidence("10.1.1.3:443", "frontend", ["aa" * 32], ["X25519"])
    result = assess(service, fe, [])
    assert result.observed == "indeterminate"
    assert result.confidence == Confidence.INDETERMINATE


def test_unreachable_backends_lower_confidence_rather_than_asserting():
    service = _service()
    fe = _evidence("10.1.1.3:443", "frontend", ["aa" * 32], ["X25519"])
    be = EndpointEvidence(endpoint="30.1.1.2:443", role="backend", passes=1)
    be.observations = [_obs("X25519", "connect_refused", endpoint="30.1.1.2:443",
                            role="backend")]
    result = assess(service, fe, [be])
    assert result.confidence == Confidence.LOW
    assert any("firewalled" in r for r in result.reasoning)


def test_layer4_frontend_declared_but_termination_observed_is_a_conflict():
    service = _service(ftype="nlb")
    fe = _evidence("10.1.1.3:443", "frontend", ["aa" * 32], ["X25519"])
    be = _evidence("30.1.1.2:443", "backend", ["bb" * 32], ["X25519"])
    result = assess(service, fe, [be])
    assert any("layer 4" in c for c in result.conflicts)


def test_unreachable_frontend_yields_not_observed():
    service = _service()
    fe = EndpointEvidence(endpoint="10.1.1.3:443", role="frontend", passes=1)
    result = assess(service, fe, [])
    assert result.observed == "not_observed"
    assert result.confidence == Confidence.INDETERMINATE


def test_assessment_never_mutates_evidence():
    """Topology is a derived view; the evidence record must survive it intact."""
    service = _service()
    fe = _evidence("10.1.1.3:443", "frontend", ["aa" * 32], ["X25519"])
    before = [
        (o.group_offered, o.outcome, o.peer.cert_fingerprint if o.peer else None)
        for o in fe.observations]
    assess(service, fe, [])
    after = [
        (o.group_offered, o.outcome, o.peer.cert_fingerprint if o.peer else None)
        for o in fe.observations]
    assert before == after


# -- rendering discipline --------------------------------------------------

def test_render_surfaces_not_observed_groups():
    """A group probed but never answered must appear in the rendered output,
    not be silently dropped into an unidentified bucket."""
    from pqcposture.report import render_endpoint_evidence
    ev = EndpointEvidence(endpoint="10.1.1.3:443", role="frontend", passes=1)
    ev.observations = [
        _obs("__realistic__", "supported", peer="aa" * 32),
        _obs("X25519", "supported", peer="aa" * 32),
        _obs("X25519MLKEM768", "timeout", peer=None),
    ]
    text = "\n".join(render_endpoint_evidence(ev))
    assert "NOT OBSERVED" in text
    assert "X25519MLKEM768" in text


def test_render_shows_inconsistency_banner():
    from pqcposture.report import render_endpoint_evidence
    ev = EndpointEvidence(endpoint="10.1.1.3:443", role="frontend", passes=2)
    ev.observations = [
        _obs("X25519MLKEM768", "supported", peer="aa" * 32, index=0),
        _obs("X25519MLKEM768", "rejected", peer="aa" * 32, index=1),
    ]
    text = "\n".join(render_endpoint_evidence(ev))
    assert "INCONSISTENT" in text
