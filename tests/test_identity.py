import hashlib

import pytest

from haris.core.identity import (
    FIELD_SEPARATOR,
    assign_identity,
    fingerprint,
    identify,
    normalise_cwe,
    normalise_url,
)
from haris.core.vuln_class import get_registry
from haris.models import Finding, Severity, VerificationTier

BASE = "https://example.com"


def make(**kwargs: object) -> Finding:
    fields: dict[str, object] = {
        "title": "Reflected XSS",
        "description": "",
        "severity": Severity.HIGH,
        "vuln_class": "xss_reflected",
        "parameter": "q",
        "method": "GET",
    }
    fields.update(kwargs)
    return Finding.model_validate(fields)


@pytest.mark.parametrize(
    ("url_a", "url_b", "relation"),
    [
        (
            "https://example.com/search?q=1&t=123",
            "https://example.com/search?t=999&q=abc",
            "equal",
        ),
        (
            "https://EXAMPLE.com:443/search/?q=1",
            "https://example.com/search?q=2",
            "equal",
        ),
        ("/search?q=1", "https://example.com/search?q=1", "equal"),
        (
            "https://example.com/search?q=1#frag",
            "https://example.com/search?q=1",
            "equal",
        ),
        ("https://example.com/search?q=1", "https://example.com/find?q=1", "different"),
        (
            "https://example.com/search?q=1",
            "http://example.com/search?q=1",
            "different",
        ),
        (
            "https://example.com/search?q=1",
            "https://example.com/search?q=1&debug=1",
            "different",
        ),
    ],
)
def test_volatile_query_values_do_not_change_identity(url_a, url_b, relation):
    """Scenario: Volatile query values do not change identity."""
    same = fingerprint(make(url=url_a), BASE) == fingerprint(make(url=url_b), BASE)
    assert same is (relation == "equal")


@pytest.mark.parametrize(
    "tier",
    [
        VerificationTier.REPLAY_VERIFIED,
        VerificationTier.EXPLOIT_VALIDATED,
        VerificationTier.REFUTED,
    ],
)
def test_fingerprint_is_unchanged_by_tier(tier):
    """Scenario: Fingerprint is unchanged by tier."""
    finding = make(url="https://example.com/search?q=1")
    assign_identity(finding, BASE)
    before = finding.fingerprint
    finding.verification.advance(tier)
    assign_identity(finding, BASE)
    assert finding.fingerprint == before
    assert finding.finding_id == before[:16]


def test_host_granularity_classes_ignore_path():
    """Scenario: Host-granularity classes ignore path."""
    assert get_registry().classes["missing_header"].granularity == "host"
    kwargs = {
        "title": "Missing Strict-Transport-Security (HSTS) header",
        "vuln_class": "missing_header",
        "parameter": "strict-transport-security",
    }
    a = make(url="https://example.com/a", **kwargs)
    b = make(url="https://example.com/b/c", **kwargs)
    assert fingerprint(a, BASE) == fingerprint(b, BASE)


def test_fingerprint_matches_documented_hash_inputs():
    finding = make(url="https://example.com/search?q=1", method="get")
    raw = FIELD_SEPARATOR.join(
        ["v1", "CWE-79", "xss_reflected", "https://example.com/search?q", "GET", "q"]
    )
    assert fingerprint(finding, BASE) == hashlib.sha256(raw.encode()).hexdigest()


def test_distinct_missing_headers_on_one_host_stay_distinct():
    hsts = make(title="Missing HSTS header", vuln_class="", parameter="")
    csp = make(title="Missing CSP header", vuln_class="", parameter="")
    assert identify(hsts, BASE)[0] == "missing_header"
    assert fingerprint(hsts, BASE) != fingerprint(csp, BASE)


def test_unmapped_finding_uses_scanner_scoped_class_and_cwe_fallback():
    nikto = make(
        title="Interesting header", vuln_class="", scanner="nikto", cwe_id="79"
    )
    nuclei = make(title="Interesting header", vuln_class="", scanner="nuclei")
    assert identify(nikto, BASE)[0] == "unclassified:nikto:interesting-header"
    assert identify(nuclei, BASE)[0] == "unclassified:nuclei:interesting-header"
    assert fingerprint(nikto, BASE) != fingerprint(nuclei, BASE)


@pytest.mark.parametrize(
    ("scanner", "title", "tags", "expected"),
    [
        ("wapiti", "Cross Site Scripting: q is vulnerable", [], "xss_reflected"),
        ("wapiti", "Blind SQL Injection: delay", [], "sqli_time"),
        ("nuclei", "Some template", ["xss"], "xss_reflected"),
        ("header_checks", "Missing X-Frame-Options header", [], "missing_header"),
        ("cookie_checks", "Cookie 'sid' missing Secure flag", [], "insecure_cookie"),
        ("misc_checks", "Accessible sensitive path: /.env", [], "sensitive_file"),
        ("sslyze", "Deprecated protocol TLSv1.0 supported", [], "tls_weak_protocol"),
    ],
)
def test_aliases_map_real_scanner_titles(scanner, title, tags, expected):
    finding = make(scanner=scanner, title=title, tags=tags, vuln_class="")
    assert identify(finding, BASE)[0] == expected


@pytest.mark.parametrize(
    ("url", "expected"),
    [
        ("https://EXAMPLE.com:443//a//b/", "https://example.com/a/b"),
        ("http://example.com:80", "http://example.com/"),
        ("https://example.com:8443/x", "https://example.com:8443/x"),
        ("https://example.com/%7Euser/%2f", "https://example.com/~user/%2F"),
        ("https://bücher.example/x?b=1&a=2&a=3", "https://xn--bcher-kva.example/x?a&b"),
        ("https://[::1]:8080/p", "https://[::1]:8080/p"),
        ("", "https://example.com/"),
    ],
)
def test_normalise_url(url, expected):
    assert normalise_url(url, BASE) == expected


@pytest.mark.parametrize(
    ("raw", "expected"),
    [("CWE-79", "CWE-79"), ("79", "CWE-79"), ("cwe-089", "CWE-89"), ("", "CWE-NONE")],
)
def test_normalise_cwe(raw, expected):
    assert normalise_cwe(raw) == expected


def test_assign_identity_uses_source_prior_unless_score_is_explicit():
    prior = make(scanner="nikto", vuln_class="")
    assign_identity(prior, BASE)
    assert prior.confidence_score == pytest.approx(0.4)
    assert prior.confidence.value == "tentative"

    explicit = make(scanner="nikto", vuln_class="", confidence_score=0.95)
    assign_identity(explicit, BASE)
    assert explicit.confidence_score == pytest.approx(0.95)
    assert explicit.confidence.value == "confirmed"
