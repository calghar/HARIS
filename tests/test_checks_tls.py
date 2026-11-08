import datetime

import pytest

pytest.importorskip("cryptography")

from cryptography.hazmat.primitives import serialization  # noqa: E402

from haris.checks.findings import prior  # noqa: E402
from haris.checks.tls_checks import TLSCheckScanner  # noqa: E402
from haris.checks.tls_probe import cert_validity  # noqa: E402
from haris.models import Scope, Severity, Target  # noqa: E402
from haris.net import NetworkPolicy, ScopedClient  # noqa: E402

from .checks_support import run_check, titles  # noqa: E402
from .tls_support import LOOPBACK, make_certificate, tls_server  # noqa: E402


def scan_tls(port: int, *, allow_private: bool = True):
    target = Target(
        base_url=f"https://{LOOPBACK}:{port}", scope=Scope(rate_limit_rps=1000.0)
    )
    with ScopedClient(target, NetworkPolicy(allow_private=allow_private)) as client:
        return run_check(TLSCheckScanner({"timeout": 5}), client)


def by_title(result, title: str):
    [found] = [f for f in result.findings if f.title == title]
    return found


def test_expired_certificate_is_critical_with_cwe_298():
    cert, key, _ = make_certificate(not_before_days=-30, not_after_days=-2)
    with tls_server(cert, key) as port:
        result = scan_tls(port)

    found = by_title(result, "TLS certificate has expired")
    assert found.severity is Severity.CRITICAL
    assert found.cwe_id == "CWE-298"
    assert "2 days ago" in found.description
    assert found.confidence_score == prior("tls_checks.cert_expired")
    assert not result.errors


def test_certificate_expiring_soon_is_medium():
    cert, key, _ = make_certificate(not_after_days=10)
    with tls_server(cert, key) as port:
        result = scan_tls(port)

    found = by_title(result, "TLS certificate expiring soon")
    assert found.severity is Severity.MEDIUM
    assert "expires in 9 days" in found.description or "expires in 10 days" in (
        found.description
    )


def test_hostname_mismatch_is_reported_with_cwe_297():
    cert, key, _ = make_certificate(dns_names=("other.test",), ips=())
    with tls_server(cert, key) as port:
        result = scan_tls(port)

    found = by_title(result, "TLS certificate does not match the hostname")
    assert found.cwe_id == "CWE-297"
    assert found.severity is Severity.HIGH


def test_untrusted_self_signed_certificate_is_reported_alone_when_otherwise_valid():
    cert, key, _ = make_certificate()
    with tls_server(cert, key) as port:
        result = scan_tls(port)

    assert titles(result.findings) == ["TLS certificate is not trusted"]
    assert result.findings[0].cwe_id == "CWE-295"


def test_deprecated_protocols_are_detected_even_when_modern_handshake_fails():
    cert, key, _ = make_certificate()
    with tls_server(cert, key, legacy_only=True) as port:
        result = scan_tls(port)

    assert titles(result.findings) == [
        "Weak TLS protocol supported: TLSv1",
        "Weak TLS protocol supported: TLSv1.1",
    ]
    assert {f.cwe_id for f in result.findings} == {"CWE-326"}
    assert {f.parameter for f in result.findings} == {"TLSv1", "TLSv1.1"}
    assert not result.errors


def test_modern_server_has_no_weak_protocol_finding():
    cert, key, _ = make_certificate()
    with tls_server(cert, key) as port:
        result = scan_tls(port)
    assert not [f for f in result.findings if "Weak TLS" in f.title]


def test_private_target_is_blocked_before_any_socket_opens():
    result = scan_tls(9, allow_private=False)
    assert result.findings == []
    assert result.errors and result.errors[0].startswith("SSRFBlocked")


def test_http_target_is_flagged_without_connecting():
    target = Target(base_url="http://example.com")
    with ScopedClient(target) as client:
        result = run_check(TLSCheckScanner(), client)
    assert titles(result.findings) == ["Target uses HTTP instead of HTTPS"]
    assert result.findings[0].cwe_id == "CWE-319"


@pytest.mark.parametrize("not_after_days", [30, 365 * 40])
def test_der_validity_parser_matches_the_certificate(not_after_days):
    """UTCTime (before 2050) and GeneralizedTime (from 2050) both decode."""
    _, _, cert = make_certificate(not_after_days=not_after_days)
    validity = cert_validity(cert.public_bytes(serialization.Encoding.DER))

    assert validity is not None
    import ssl

    expected = cert.not_valid_after_utc.replace(microsecond=0)
    got = datetime.datetime.fromtimestamp(
        ssl.cert_time_to_seconds(validity["notAfter"]), datetime.UTC
    )
    assert got == expected.replace(microsecond=0)


def test_garbage_certificate_has_no_validity():
    assert cert_validity(b"\x30\x03\x01") is None
