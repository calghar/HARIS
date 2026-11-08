import pytest
import requests

from haris.checks.findings import prior
from haris.checks.header_checks import SecurityHeaderScanner
from haris.checks.header_policy import csp_issues, hsts_issues
from haris.core.context_extract import extract_context
from haris.core.identity import fingerprint
from haris.models import Finding, ScanContext, Severity

from .checks_support import HTML_SHELL, html, run_check, site, titles

GOOD_CSP = "default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'self'"
STRICT_TAIL = "; object-src 'none'; base-uri 'self'"
GOOD_HSTS = "max-age=31536000; includeSubDomains"
HTML_HEADERS = {
    "Strict-Transport-Security": GOOD_HSTS,
    "Content-Security-Policy": GOOD_CSP,
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "camera=()",
}
ALL_MISSING = {
    "Missing Strict-Transport-Security (HSTS) header",
    "Missing Content-Security-Policy (CSP) header",
    "Missing X-Content-Type-Options header",
    "Missing X-Frame-Options header",
    "Missing Referrer-Policy header",
    "Missing Permissions-Policy header",
}


def scan_front(reply, **kw) -> list[Finding]:
    return run_check(SecurityHeaderScanner(), site({"/": reply}, **kw)).findings


def test_html_page_without_headers_reports_every_applicable_header():
    assert set(titles(scan_front(html()))) == ALL_MISSING


def test_x_xss_protection_is_not_reported():
    assert not [t for t in titles(scan_front(html())) if "XSS" in t]


def test_page_with_all_headers_has_no_findings():
    assert scan_front(html(**HTML_HEADERS)) == []


def test_json_response_only_needs_nosniff_and_hsts():
    reply = (200, {"Content-Type": "application/json"}, b"{}")
    assert set(titles(scan_front(reply))) == {
        "Missing Strict-Transport-Security (HSTS) header",
        "Missing X-Content-Type-Options header",
    }


def test_http_site_does_not_need_hsts():
    found = scan_front(html(), base_url="http://example.com")
    assert "Missing Strict-Transport-Security (HSTS) header" not in titles(found)


@pytest.mark.parametrize("status", [301, 403, 404, 500])
def test_non_success_final_status_reports_no_missing_headers(status):
    assert scan_front(html(status=status)) == []


def test_frame_ancestors_in_csp_replaces_x_frame_options():
    headers = {**HTML_HEADERS, "Content-Security-Policy": GOOD_CSP}
    headers["Content-Security-Policy"] += "; frame-ancestors 'none'"
    del headers["X-Frame-Options"]
    assert scan_front(html(**headers)) == []


def test_report_only_csp_is_noted_not_enforced():
    headers = {k: v for k, v in HTML_HEADERS.items() if k != "Content-Security-Policy"}
    found = scan_front(html(**headers, **{"Content-Security-Policy-Report-Only": "x"}))
    [csp] = found
    assert "report-only" in csp.description


def test_missing_header_confidence_comes_from_config():
    found = scan_front(html())
    assert {f.confidence_score for f in found} == {
        prior("header_checks.missing_header")
    }
    assert {f.cwe_id for f in found} == {"CWE-693"}


@pytest.mark.parametrize(
    ("csp", "expected"),
    [
        (GOOD_CSP, set()),
        (
            "img-src *",
            {"no-script-restriction", "missing-object-src", "missing-base-uri"},
        ),
        (
            "script-src 'self' 'unsafe-inline'" + STRICT_TAIL,
            {"unsafe-inline"},
        ),
        (
            "script-src 'nonce-abc' 'unsafe-inline'" + STRICT_TAIL,
            set(),
        ),
        (
            "script-src 'self' 'unsafe-eval'" + STRICT_TAIL,
            {"unsafe-eval"},
        ),
        (
            "script-src https: 'self'" + STRICT_TAIL,
            {"wildcard-source"},
        ),
        ("default-src *; base-uri 'self'", {"wildcard-source"}),
        ("default-src 'self'", {"missing-base-uri"}),
    ],
)
def test_csp_quality_issues(csp, expected):
    assert {i.key for i in csp_issues(csp)} == expected


@pytest.mark.parametrize(
    ("hsts", "expected"),
    [
        (GOOD_HSTS, set()),
        (
            "includeSubDomains",
            {
                "no-max-age",
            },
        ),
        ("max-age=0; includeSubDomains", {"max-age-zero"}),
        ("max-age=300; includeSubDomains", {"short-max-age"}),
        ("max-age=31536000", {"no-include-subdomains"}),
        ("max-age=31536000; preload", {"no-include-subdomains", "invalid-preload"}),
        ("max-age=31536000; includeSubDomains; preload", set()),
        ("max-age=nonsense", {"no-max-age", "no-include-subdomains"}),
    ],
)
def test_hsts_quality_issues(hsts, expected):
    assert {i.key for i in hsts_issues(hsts)} == expected


def test_weak_policies_become_findings_with_distinct_parameters():
    headers = {
        **HTML_HEADERS,
        "Content-Security-Policy": "script-src 'unsafe-inline' 'unsafe-eval'",
        "Strict-Transport-Security": "max-age=300",
    }
    found = scan_front(html(**headers))
    params = {f.parameter for f in found}

    assert "Content-Security-Policy/unsafe-inline" in params
    assert "Content-Security-Policy/unsafe-eval" in params
    assert "Strict-Transport-Security/short-max-age" in params
    assert len({fingerprint(f) for f in found}) == len(found)
    csp = next(f for f in found if f.parameter.endswith("unsafe-eval"))
    assert csp.confidence_score == prior("header_checks.weak_csp")
    assert csp.evidence.startswith("Content-Security-Policy: script-src")


@pytest.mark.parametrize(
    "server", ["nginx/1.18.0", "Apache/2.4.41 (Ubuntu)", "Microsoft-IIS/10.0"]
)
def test_versioned_server_banner_is_reported(server):
    found = scan_front(html(**HTML_HEADERS, Server=server))
    assert titles(found) == ["Server header discloses version information"]
    assert found[0].vuln_class == "banner_disclosure"


@pytest.mark.parametrize("server", ["cloudflare", "ECS (dcb/7F83)", "nginx", "gws"])
def test_unversioned_server_banner_is_not_reported(server):
    assert scan_front(html(**HTML_HEADERS, Server=server)) == []


def test_tech_headers_populate_cross_scanner_context():
    headers = {**HTML_HEADERS, "Server": "nginx/1.18.0", "X-Powered-By": "PHP/8.1"}
    result = run_check(SecurityHeaderScanner(), site({"/": html(**headers)}))
    context = ScanContext()

    extract_context("header_checks", result, context)

    assert context.server_headers["server"] == "nginx/1.18.0"
    assert context.server_headers["x-powered-by"] == "PHP/8.1"
    assert "php/8.1" in context.detected_technologies


def test_set_cookie_headers_are_left_to_the_cookie_check():
    reply = html(HTML_SHELL, **HTML_HEADERS, **{"Set-Cookie": "sid=1; Path=/"})
    assert scan_front(reply) == []


def test_unreachable_front_page_is_an_error_not_a_finding():
    def refuse(_request):
        raise requests.ConnectionError("refused")

    net = site({}, fallback=refuse)
    result = run_check(SecurityHeaderScanner(), net)
    assert result.findings == [] and result.errors


def test_missing_hsts_is_medium_severity():
    found = scan_front(html())
    hsts = next(f for f in found if f.parameter == "Strict-Transport-Security")
    assert hsts.severity is Severity.MEDIUM
