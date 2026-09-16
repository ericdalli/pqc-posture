"""Parser tests.

These exist because the scanner's correctness lives almost entirely in how it
reads `s_client` output, and that output cannot be exercised on a host without
OpenSSL 3.5 and without reachable endpoints. Fixtures make the parsing
testable anywhere, including in CI.
"""

from __future__ import annotations

import pathlib
import sys

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "src"))

from pqcposture import openssl as ossl  # noqa: E402
from pqcposture.cli import parse_target  # noqa: E402
from pqcposture.models import (  # noqa: E402
    GroupKind, Outcome, ProbeResult, ProtocolSupport, TargetResult, kind_of,
)
from pqcposture.scoring import score_target  # noqa: E402

FIXTURES = pathlib.Path(__file__).parent / "fixtures"


def load(name: str) -> str:
    return (FIXTURES / name).read_text()


# -- handshake detection ---------------------------------------------------

@pytest.mark.parametrize("fixture,expected", [
    ("hybrid_success.txt", True),
    ("classical_success.txt", True),
    ("brief_hybrid.txt", True),
    ("alert40_no_shared_group.txt", False),
    ("reset_large_clienthello.txt", False),
    ("protocol_version_alert.txt", False),
    ("connect_refused.txt", False),
])
def test_handshake_detection(fixture, expected):
    assert ossl.handshake_succeeded(load(fixture)) is expected


def test_failed_handshake_prints_misleading_success_markers():
    """Guard the specific trap: a rejected handshake still emits a cipher line
    and 'Verify return code: 0 (ok)'."""
    text = load("alert40_no_shared_group.txt")
    assert "Cipher is (NONE)" in text
    assert "Verify return code: 0 (ok)" in text
    assert ossl.handshake_succeeded(text) is False


# -- negotiated group ------------------------------------------------------

def test_negotiated_group_from_explicit_line():
    assert ossl.parse_negotiated_group(load("hybrid_success.txt")) == "X25519MLKEM768"


def test_negotiated_group_falls_back_to_server_temp_key():
    """Clients before 3.2 omit the explicit line; -brief only has Temp Key."""
    assert ossl.parse_negotiated_group(load("brief_hybrid.txt")) == "X25519MLKEM768"


def test_negotiated_group_classical():
    assert ossl.parse_negotiated_group(load("classical_success.txt")) == "X25519"


# -- failure classification ------------------------------------------------

def test_alert_is_rejection_not_transport_failure():
    outcome, alert, _ = ossl.classify_failure(load("alert40_no_shared_group.txt"), 1)
    assert outcome == Outcome.REJECTED.value
    assert alert == "handshake_failure"


def test_reset_without_alert_is_transport_failure():
    outcome, alert, detail = ossl.classify_failure(
        load("reset_large_clienthello.txt"), 1)
    assert outcome == Outcome.TRANSPORT_FAILED.value
    assert alert is None
    assert "no TLS alert" in detail


def test_protocol_version_classified_separately():
    outcome, _, _ = ossl.classify_failure(load("protocol_version_alert.txt"), 1)
    assert outcome == Outcome.PROTOCOL_UNSUPPORTED.value


def test_connect_refused():
    outcome, _, _ = ossl.classify_failure(load("connect_refused.txt"), 1)
    assert outcome == Outcome.CONNECT_REFUSED.value


# -- ancillary parsing -----------------------------------------------------

def test_bytes_written_reflects_clienthello_size():
    assert ossl.parse_bytes_written(load("hybrid_success.txt")) == 1547
    assert ossl.parse_bytes_written(load("classical_success.txt")) == 324


def test_cipher_and_version():
    version, cipher = ossl.parse_cipher_and_version(load("hybrid_success.txt"))
    assert version == "TLSv1.3"
    assert cipher == "TLS_AES_256_GCM_SHA384"


def test_brief_mode_cipher_and_version():
    version, cipher = ossl.parse_cipher_and_version(load("brief_hybrid.txt"))
    assert version == "TLSv1.3"
    assert cipher == "TLS_AES_256_GCM_SHA384"


def test_verify_ok_and_failure():
    assert ossl.parse_verify(load("hybrid_success.txt")) == (True, None)
    ok, err = ossl.parse_verify(load("classical_success.txt"))
    assert ok is False
    assert "local issuer" in err


def test_chain_parsing_takes_leaf_not_intermediate():
    fields = ossl.parse_chain(load("hybrid_success.txt"))
    assert fields["subject"] == "CN = pqc-lab.example.com"
    assert fields["key_algorithm"] == "rsaEncryption"
    assert fields["key_bits"] == 2048          # not the 4096-bit intermediate
    assert fields["signature_algorithm"] == "RSA-SHA256"
    assert fields["chain_length"] == 2
    assert fields["not_after"] == "Nov  9 23:59:59 2026 GMT"


def test_chain_parsing_ecdsa_leaf():
    fields = ossl.parse_chain(load("classical_success.txt"))
    assert fields["key_algorithm"] == "id-ecPublicKey"
    assert fields["key_bits"] == 256


# -- group catalog ---------------------------------------------------------

@pytest.mark.parametrize("name,kind", [
    ("X25519MLKEM768", GroupKind.HYBRID),
    ("x25519mlkem768", GroupKind.HYBRID),      # matching is case-insensitive
    ("SecP384r1MLKEM1024", GroupKind.HYBRID),
    ("MLKEM768", GroupKind.PURE_PQ),
    ("X25519", GroupKind.CLASSICAL_EC),
    ("ffdhe2048", GroupKind.CLASSICAL_FF),
])
def test_group_classification(name, kind):
    assert kind_of(name) == kind


def test_unknown_group_is_not_classified():
    assert kind_of("NotARealGroup") is None


# -- target parsing --------------------------------------------------------

@pytest.mark.parametrize("raw,expected", [
    ("example.com", ("example.com", 443, None)),
    ("example.com:8443", ("example.com", 8443, None)),
    ("10.0.0.5:443@app.example.com", ("10.0.0.5", 443, "app.example.com")),
    ("[2606:4700::1111]:443", ("2606:4700::1111", 443, None)),
])
def test_parse_target(raw, expected):
    assert parse_target(raw) == expected


# -- scoring ---------------------------------------------------------------

def _target(**kwargs) -> TargetResult:
    result = TargetResult(host="t.example.com", port=443, sni="t.example.com",
                          reachable=True)
    result.protocols = ProtocolSupport(tls1_3=True, tls1_2=False,
                                       tls1_1=False, tls1_0=False)
    for key, value in kwargs.items():
        setattr(result, key, value)
    return result


def test_hybrid_preferred_grades_a():
    result = score_target(_target(
        hybrid_supported=True, hybrid_preferred=True,
        default_negotiated_group="X25519MLKEM768",
        supported_groups=["X25519MLKEM768", "X25519"]))
    assert result.grade == "A"
    assert any(f.code == "PQ_HYBRID_DEFAULT" for f in result.findings)


def test_capability_without_preference_is_flagged_and_downgraded():
    supported = score_target(_target(
        hybrid_supported=True, hybrid_preferred=False,
        default_negotiated_group="X25519",
        supported_groups=["X25519MLKEM768", "X25519"]))
    preferred = score_target(_target(
        hybrid_supported=True, hybrid_preferred=True,
        default_negotiated_group="X25519MLKEM768",
        supported_groups=["X25519MLKEM768", "X25519"]))
    assert supported.score < preferred.score
    assert any(f.code == "PQ_HYBRID_NOT_PREFERRED" for f in supported.findings)


def test_no_pq_support_is_high_severity():
    result = score_target(_target(
        default_negotiated_group="X25519", supported_groups=["X25519"]))
    finding = next(f for f in result.findings if f.code == "NO_PQ_KEX")
    assert finding.severity == "high"


def test_unreachable_scores_zero_and_says_unknown():
    result = score_target(TargetResult(host="x", port=443, sni="x",
                                       reachable=False))
    assert result.score == 0
    assert "unknown, not good" in result.findings[0].message


def test_large_clienthello_finding_zeroes_interop_component():
    clean = score_target(_target(
        hybrid_supported=True, hybrid_preferred=True,
        default_negotiated_group="X25519MLKEM768",
        supported_groups=["X25519MLKEM768"]))
    broken = score_target(_target(
        hybrid_supported=True, hybrid_preferred=True,
        default_negotiated_group="X25519MLKEM768",
        supported_groups=["X25519MLKEM768"],
        large_clienthello_suspected=True))
    assert clean.score - broken.score == 10
    assert any(f.code == "LARGE_CLIENTHELLO_INTOLERANCE"
               for f in broken.findings)


def test_certificate_expiry_is_computed_from_chain_text():
    from pqcposture.models import CertificateInfo
    result = _target(hybrid_supported=True, hybrid_preferred=True,
                     default_negotiated_group="X25519MLKEM768",
                     supported_groups=["X25519MLKEM768"])
    result.certificate = CertificateInfo(
        subject="CN = t.example.com", not_after="Nov  9 23:59:59 2026 GMT",
        key_algorithm="rsaEncryption", key_bits=2048)
    scored = score_target(result)
    assert scored.certificate.days_remaining is not None


def test_classical_signature_is_informational_not_a_penalty():
    from pqcposture.models import CertificateInfo
    result = _target(hybrid_supported=True, hybrid_preferred=True,
                     default_negotiated_group="X25519MLKEM768",
                     supported_groups=["X25519MLKEM768"])
    result.certificate = CertificateInfo(
        signature_algorithm="RSA-SHA256", key_algorithm="rsaEncryption",
        key_bits=2048, not_after="Nov  9 23:59:59 2030 GMT")
    scored = score_target(result)
    sig = next(f for f in scored.findings if f.code == "CERT_SIG_CLASSICAL")
    assert sig.severity == "info"
    assert scored.grade == "A"


# -- regressions -----------------------------------------------------------
# Both of these were live bugs caught by the first end-to-end run against a
# host with OpenSSL 3.0. They are the difference between "this scanner cannot
# ask the question" and "this endpoint gave a worrying answer", and conflating
# them produced a confident, high-severity, entirely fictional finding.

def test_local_group_rejection_is_not_a_network_failure():
    outcome, alert, _ = ossl.classify_failure(
        load("local_group_unsupported.txt"), 1)
    assert outcome == Outcome.CLIENT_UNSUPPORTED.value
    assert alert is None


def test_client_unsupported_never_implies_large_clienthello_intolerance():
    """A group the client cannot offer must not feed the middlebox heuristic."""
    result = _target(supported_groups=["X25519"],
                     default_negotiated_group="X25519")
    result.probes = [
        ProbeResult(group="X25519", outcome=Outcome.SUPPORTED.value),
        ProbeResult(group="X25519MLKEM768",
                    outcome=Outcome.CLIENT_UNSUPPORTED.value),
    ]
    scored = score_target(result)
    assert not any(f.code == "LARGE_CLIENTHELLO_INTOLERANCE"
                   for f in scored.findings)


def test_generic_temp_key_reports_curve_not_algorithm_family():
    text = "Server Temp Key: ECDH, P-256, 256 bits\n"
    assert ossl.parse_negotiated_group(text) == "P-256"


def test_named_temp_key_reports_the_group():
    text = "Server Temp Key: X25519MLKEM768, 192 bits\n"
    assert ossl.parse_negotiated_group(text) == "X25519MLKEM768"


def test_ec_certificate_chain_parses():
    """EC keys print a curve name where RSA prints a bit count. Requiring
    digits silently dropped the whole certificate block for every ECDSA
    endpoint — which is most of the modern web."""
    fields = ossl.parse_chain((FIXTURES / "ec_cloudflare.txt").read_text())
    assert fields["key_algorithm"] == "EC"
    assert fields["key_curve"] == "prime256v1"
    assert fields["key_bits"] == 256
    assert fields["signature_algorithm"] == "ecdsa-with-SHA256"
    assert fields["subject"] == "CN=cloudflare.com"
    assert fields["chain_length"] == 3


def test_rsa_certificate_chain_still_parses():
    """Guard the other branch of the same regex."""
    fields = ossl.parse_chain((FIXTURES / "hybrid_success.txt").read_text())
    assert fields["key_algorithm"] == "rsaEncryption"
    assert fields["key_bits"] == 2048
    assert "key_curve" not in fields


@pytest.mark.parametrize("line,expected", [
    ("Peer Temp Key: X25519, 253 bits", "X25519"),
    ("Server Temp Key: X25519, 253 bits", "X25519"),
    ("Peer Temp Key: X25519MLKEM768, 192 bits", "X25519MLKEM768"),
    ("Peer Temp Key: ECDH, P-256, 256 bits", "P-256"),
])
def test_temp_key_wording_variants(line, expected):
    """OpenSSL 3.5 says "Peer Temp Key"; older releases say "Server Temp Key".
    Matching only the old wording returned an unknown negotiated group for any
    server omitting the explicit "Negotiated TLS1.3 group" line -- github.com
    among them."""
    assert ossl.parse_negotiated_group(line + "\n") == expected


def test_github_fixture_reports_its_group():
    text = (FIXTURES / "peer_temp_key_github.txt").read_text()
    assert "Negotiated TLS1.3 group" not in text
    assert ossl.parse_negotiated_group(text) == "X25519"
