from urllib.parse import parse_qs, quote, urlsplit

import pytest
import requests

from haris.checks.cache_checks import CacheControlScanner
from haris.checks.findings import prior
from haris.checks.method_checks import HttpMethodScanner
from haris.checks.redirect_checks import (
    CANARY_HOST,
    CANARY_URL,
    PARAMETERS,
    OpenRedirectScanner,
)
from haris.checks.sri_checks import SriScanner
from haris.models import Scope, Severity

from .checks_support import HTML_SHELL, NOT_FOUND, html, run_check, site

SCRIPTS = b"""<html><head>
<script src="https://cdn.vendor.test/lib.js"></script>
<script src="//cdn2.vendor.test/a.js" integrity="sha384-abc" crossorigin></script>
<script src="//cdn3.vendor.test/b.js"></script>
<script src="/static/main.js"></script>
<script src="https://static.example.com/own.js"></script>
<script>inline()</script>
<link rel="stylesheet" href="https://fonts.vendor.test/x.css">
<link rel="icon" href="https://img.vendor.test/favicon.ico">
</head></html>"""


def test_third_party_resources_without_integrity_are_reported():
    result = run_check(SriScanner(), site({"/": html(SCRIPTS)}))

    assert sorted(f.parameter for f in result.findings) == [
        "https://cdn.vendor.test/lib.js",
        "https://cdn3.vendor.test/b.js",
        "https://fonts.vendor.test/x.css",
    ]
    assert {f.cwe_id for f in result.findings} == {"CWE-353"}
    assert {f.confidence_score for f in result.findings} == {
        prior("sri_checks.missing_sri")
    }


def test_same_origin_subdomain_and_integrity_resources_are_clean():
    page = (
        b'<script src="/a.js"></script><script src="https://cdn.example.com/b.js">'
        b'</script><script src="https://x.test/c.js" integrity="sha384-x"></script>'
    )
    assert run_check(SriScanner(), site({"/": html(page)})).findings == []


def test_non_html_front_page_is_not_parsed_for_sri():
    reply = (200, {"Content-Type": "application/json"}, SCRIPTS)
    assert run_check(SriScanner(), site({"/": reply})).findings == []


def test_session_setting_page_without_no_store_is_reported():
    page = html(**{"Set-Cookie": "sid=abc; Path=/"})
    result = run_check(CacheControlScanner(), site({"/": page}))

    [found] = result.findings
    assert found.vuln_class == "cache_sensitive"
    assert found.cwe_id == "CWE-525"
    assert found.evidence == "Cache-Control: (absent)"
    assert found.confidence_score == prior("cache_checks.sensitive_cacheable")


def test_no_store_on_session_page_is_clean():
    headers = {"Set-Cookie": "sid=abc", "Cache-Control": "no-store, max-age=0"}
    assert run_check(CacheControlScanner(), site({"/": html(**headers)})).findings == []


def test_public_cache_header_on_session_page_is_reported():
    headers = {"Set-Cookie": "sid=abc", "Cache-Control": "public, max-age=600"}
    result = run_check(CacheControlScanner(), site({"/": html(**headers)}))
    assert [f.evidence for f in result.findings] == [
        "Cache-Control: public, max-age=600"
    ]


def test_login_page_on_normal_host_is_checked_and_flagged():
    page = html(b"<form>Sign in</form>")
    result = run_check(CacheControlScanner(), site({"/login": page}))
    [found] = result.findings
    assert found.url.endswith("/login")


def test_catch_all_host_login_page_is_not_judged():
    result = run_check(CacheControlScanner(), site({}, fallback=html(HTML_SHELL)))
    assert result.findings == []


def test_page_without_cookie_or_account_paths_is_clean():
    assert run_check(CacheControlScanner(), site({"/": html()})).findings == []


def test_non_session_cookie_does_not_make_a_page_sensitive():
    page = html(**{"Set-Cookie": "_ga=1; Path=/"})
    assert run_check(CacheControlScanner(), site({"/": page})).findings == []


def methods_site(allow: str, trace=None, **scope):
    def handler(request: requests.PreparedRequest):
        if request.method == "OPTIONS":
            return 204, {"Allow": allow}, b""
        if request.method == "TRACE" and trace is not None:
            return trace(request)
        return html()

    return site({}, fallback=handler, scope=Scope(rate_limit_rps=1000.0, **scope))


def echo(request: requests.PreparedRequest):
    lines = "".join(f"{k}: {v}\r\n" for k, v in request.headers.items())
    return (
        200,
        {"Content-Type": "message/http"},
        f"TRACE / HTTP/1.1\r\n{lines}".encode(),
    )


def test_risky_verbs_in_allow_header_are_reported():
    result = run_check(HttpMethodScanner(), methods_site("GET, HEAD, PUT, DELETE"))
    [found] = result.findings
    assert found.title == "Risky HTTP methods advertised: PUT, DELETE"
    assert found.vuln_class == "http_methods"
    assert found.confidence_score == prior("method_checks.options_methods")


def test_safe_allow_header_is_clean():
    result = run_check(HttpMethodScanner(), methods_site("GET, HEAD, OPTIONS"))
    assert result.findings == []


def test_trace_echo_is_reported_when_scope_allows_trace():
    net = methods_site(
        "GET", trace=echo, allowed_methods=["GET", "HEAD", "OPTIONS", "TRACE"]
    )
    [found] = run_check(HttpMethodScanner(), net).findings
    assert found.vuln_class == "http_trace"
    assert found.confidence_score == prior("method_checks.trace_enabled")


def test_trace_rejected_by_server_is_clean():
    net = methods_site(
        "GET",
        trace=lambda _req: (405, {}, b"no"),
        allowed_methods=["GET", "HEAD", "OPTIONS", "TRACE"],
    )
    assert run_check(HttpMethodScanner(), net).findings == []


def test_trace_is_not_sent_when_scope_forbids_it():
    net = methods_site("GET", trace=echo)
    result = run_check(HttpMethodScanner(), net)
    assert result.findings == []
    assert "TRACE" not in {r.method for r in net.sent}


def redirecting(honoured: set[str], path: str = "/login", relative_only=False):
    """A host whose *path* redirects to the URL given in any honoured parameter."""

    def handler(request: requests.PreparedRequest):
        parts = urlsplit(request.url or "")
        query = parse_qs(parts.query)
        if parts.path == path:
            for name in honoured:
                if name in query:
                    target = query[name][0]
                    if relative_only and not target.startswith("/"):
                        continue
                    return 302, {"Location": target}, b""
        return NOT_FOUND

    return site({}, fallback=handler)


def test_open_redirect_names_only_the_honoured_parameter():
    net = redirecting({"next"})
    [found] = run_check(OpenRedirectScanner(), net).findings

    assert found.title == "Open redirect via 'next' parameter"
    assert found.parameter == "next"
    assert found.severity is Severity.MEDIUM
    assert found.cwe_id == "CWE-601"
    assert found.confidence_score == prior("redirect_checks.open_redirect")


def test_each_honoured_parameter_is_reported_separately():
    net = redirecting({"next", "returnUrl"})
    found = run_check(OpenRedirectScanner(), net).findings
    assert sorted(f.parameter for f in found) == ["next", "returnUrl"]


def test_canary_host_is_never_requested():
    net = redirecting({"next"})
    run_check(OpenRedirectScanner(), net)
    assert CANARY_HOST not in net.resolver_calls
    assert set(net.resolver_calls) == {"example.com"}


def test_relative_only_redirects_are_not_open():
    net = redirecting({"next"}, relative_only=True)
    assert run_check(OpenRedirectScanner(), net).findings == []


def test_unconditional_redirect_to_login_is_not_open():
    net = site({}, fallback=lambda _req: (302, {"Location": "/login"}, b""))
    assert run_check(OpenRedirectScanner(), net).findings == []


def test_every_parameter_is_tried_in_the_combined_probe():
    net = redirecting(set(PARAMETERS))
    run_check(OpenRedirectScanner(), net)
    combined = next(r.url or "" for r in net.sent if "next=" in (r.url or ""))
    assert all(f"{p}=" in combined for p in PARAMETERS)
    assert quote(CANARY_URL, safe="") in combined


@pytest.mark.parametrize("scanner", [SriScanner, CacheControlScanner])
def test_checks_report_network_failure_as_error(scanner):
    def refuse(_request):
        raise requests.ConnectionError("refused")

    result = run_check(scanner(), site({}, fallback=refuse))
    assert result.findings == []
    assert result.errors and "TransportError" in result.errors[0]
