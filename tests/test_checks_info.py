import json

import pytest

from haris.checks.findings import prior
from haris.checks.info_disclosure import InfoDisclosureScanner
from haris.models import Finding, Severity

from .checks_support import HTML_SHELL, NOT_FOUND, html, run_check, site, titles

WAF_BLOCK: tuple[int, dict[str, str], bytes] = (
    403,
    {"Content-Type": "text/html"},
    b"<html><title>Blocked</title>Request blocked by security policy</html>",
)
JSON = {"Content-Type": "application/json"}
NO_PROBES = {"check_error_pages": False, "check_html_comments": False}


def errors(body: str) -> list[Finding]:
    """Findings when every unknown path answers 500 with *body*."""
    fallback = (500, {"Content-Type": "text/html"}, body.encode())
    scanner = InfoDisclosureScanner({"check_debug_endpoints": False})
    result = run_check(scanner, site({"/": html()}, fallback=fallback))
    return [f for f in result.findings if f.vuln_class == "verbose_error"]


def comments(comment: str) -> list[Finding]:
    page = html(f"<html><body><!-- {comment} --></body></html>".encode())
    scanner = InfoDisclosureScanner(
        {"check_error_pages": False, "check_debug_endpoints": False}
    )
    result = run_check(scanner, site({"/": page}))
    return [f for f in result.findings if f.vuln_class == "html_comment_leak"]


@pytest.mark.parametrize(
    "body",
    [
        "Express 2024 conference tickets",
        "Spring 2025 sale",
        "Flask 12 recipes",
        "Django 3 hours ago",
        "Express yourself",
    ],
)
def test_framework_names_in_prose_are_not_version_disclosure(body):
    assert errors(body) == []


@pytest.mark.parametrize(
    ("body", "label"),
    [
        ("Cannot GET / - Express 4.17.1", "Express.js version disclosure"),
        ("Powered by Django/4.2.1", "Django version disclosure"),
        ("Laravel 10.0.1 error", "Laravel version disclosure"),
    ],
)
def test_framework_with_version_is_still_reported(body, label):
    [found] = errors(body)
    assert label in found.title
    assert found.severity is Severity.MEDIUM


@pytest.mark.parametrize(
    "body",
    [
        "Caused by: user cancelled the request",
        "Caused by: network timeout",
        "caused by: Exception",
    ],
)
def test_caused_by_prose_is_not_a_java_exception_chain(body):
    assert errors(body) == []


@pytest.mark.parametrize(
    "body",
    [
        "Caused by: java.lang.NullPointerException",
        "Caused by: com.acme.db.ConnectionError: refused",
    ],
)
def test_caused_by_with_exception_class_is_reported(body):
    [found] = errors(body)
    assert found.severity is Severity.HIGH
    assert "Caused by" in found.title


def test_url_containing_srv_is_not_a_filesystem_path():
    assert errors("See https://cdn.example.com/srv/app/docs") == []


def test_real_filesystem_path_is_reported():
    [found] = errors("Warning in /var/www/html/index.php on line 3")
    assert "filesystem path" in found.title


def test_error_page_confidence_comes_from_config():
    [found] = errors("Traceback (most recent call last)")
    assert found.confidence_score == prior("info_disclosure.verbose_error")


@pytest.mark.parametrize(
    "comment",
    [
        "hackathon sign-up opens soon",
        "this is a hack-free zone",
        "todolist widget",
        "Fixed header layout",
        "tokenizer settings",
    ],
)
def test_ordinary_words_in_comments_are_not_markers(comment):
    assert comments(comment) == []


@pytest.mark.parametrize(
    ("comment", "severity"),
    [
        ("TODO: remove before launch", Severity.INFO),
        ("HACK to work around cache", Severity.INFO),
        ("FIXME later", Severity.INFO),
        ("password: hunter2", Severity.MEDIUM),
        ("api_key=abcd1234", Severity.MEDIUM),
        ("-----BEGIN RSA PRIVATE KEY-----", Severity.HIGH),  # pragma: allowlist secret
    ],
)
def test_real_markers_and_credentials_in_comments_are_reported(comment, severity):
    [found] = comments(comment)
    assert found.severity is severity
    assert found.confidence_score == prior("info_disclosure.html_comment")


def debug_titles(net) -> list[str]:
    scanner = InfoDisclosureScanner(NO_PROBES)
    return titles(run_check(scanner, net).findings)


def test_spa_catch_all_has_no_debug_or_version_findings():
    assert debug_titles(site({}, fallback=html(HTML_SHELL))) == []


def test_waf_block_page_has_no_debug_or_version_findings():
    assert debug_titles(site({}, fallback=WAF_BLOCK)) == []


def test_html_page_for_actuator_env_is_not_a_finding():
    net = site({"/actuator/env": html(b"<h1>Welcome</h1>")})
    assert "Exposed debug endpoint: /actuator/env" not in debug_titles(net)


def test_real_actuator_env_is_critical_and_validated():
    body = json.dumps({"propertySources": [{"name": "systemEnvironment"}]}).encode()
    net = site({"/actuator/env": (200, JSON, body)}, fallback=NOT_FOUND)
    [found] = run_check(InfoDisclosureScanner(NO_PROBES), net).findings

    assert found.severity is Severity.CRITICAL
    assert found.confidence_score == prior("info_disclosure.debug_endpoint_validated")
    assert found.confidence_score > prior("info_disclosure.debug_endpoint")


def test_version_endpoint_needs_a_version_and_has_no_outdated_server_tag():
    scanner = InfoDisclosureScanner(NO_PROBES)
    with_version = site({"/version": (200, JSON, b'{"version": "1.2.3"}')})
    without = site({"/version": (200, JSON, b'{"status": "up"}')})

    [found] = run_check(scanner, with_version).findings

    assert found.vuln_class == "version_disclosure"
    assert found.cwe_id == "CWE-200"
    assert "outdated_server" not in found.tags
    assert run_check(scanner, without).findings == []
