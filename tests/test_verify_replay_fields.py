from html import escape
from urllib.parse import parse_qs, urlsplit

import pytest
import requests

from haris.models import Finding, Scope, Severity, VerificationTier
from haris.verify.probe import FORM_HEADERS, build_request
from haris.verify.replay import replay
from tests.checks_support import html, site
from tests.fake_transport import Reply
from tests.verify_server import case, fast_settings

BASE = "http://dvwa"
FORM_URL = "https://example.com/form"
VALUE = "probe-value"
T = VerificationTier


def finding(
    url: str, parameter: str, method: str, request_example: str = ""
) -> Finding:
    return Finding(
        title="Cross Site Scripting",
        description="",
        severity=Severity.HIGH,
        url=url,
        parameter=parameter,
        method=method,
        request_example=request_example,
    )


@pytest.mark.parametrize(
    ("found", "url", "body"),
    [
        (
            finding(
                "/vulnerabilities/exec/",
                "ip",
                "POST",
                'curl "http://dvwa/vulnerabilities/exec/" -d "ip=;env;&Submit=Submit"',
            ),
            "/vulnerabilities/exec/",
            "ip=probe-value&Submit=Submit",
        ),
        (
            finding("/vulnerabilities/exec/", "ip", "POST"),
            "/vulnerabilities/exec/",
            "ip=probe-value",
        ),
        (
            finding(
                "/up/",
                "uploaded",
                "POST",
                'curl "http://dvwa/up/" -F "Upload=Upload" -F "uploaded=@f.png"',
            ),
            "/up/",
            "uploaded=probe-value",
        ),
        (
            finding(
                "/login/",
                "user",
                "POST",
                'curl "http://dvwa/login/" -d "user=a&pass=[REDACTED]&Login=Go"',
            ),
            "/login/",
            "user=probe-value&Login=Go",
        ),
        (
            finding(
                "/vulnerabilities/exec/",
                "ip",
                "POST",
                'curl "http://dvwa/other/" -d "ip=1&Submit=Submit"',
            ),
            "/vulnerabilities/exec/",
            "ip=probe-value",
        ),
        (
            finding("/p/", "a", "POST", 'curl "http://dvwa/p/" -d "a=1'),
            "/p/",
            "a=probe-value",
        ),
    ],
    ids=[
        "post-keeps-sibling-fields",
        "post-without-stored-request",
        "multipart-falls-back",
        "redacted-sibling-dropped",
        "other-path-ignored",
        "unparseable-falls-back",
    ],
)
def test_post_body_keeps_stored_siblings(found: Finding, url: str, body: str) -> None:
    method, built, content, headers = build_request(found, BASE, VALUE)
    assert (method, built, headers) == ("POST", f"{BASE}{url}", FORM_HEADERS)
    assert content is not None
    assert content.decode() == body


@pytest.mark.parametrize(
    ("found", "query"),
    [
        (
            finding(
                "/vulnerabilities/sqli/",
                "id",
                "GET",
                'curl "http://dvwa/vulnerabilities/sqli/?id=default&Submit=Submit"',
            ),
            "id=probe-value&Submit=Submit",
        ),
        (
            finding("/vulnerabilities/sqli/?id=1&keep=y", "id", "GET"),
            "id=probe-value&keep=y",
        ),
        (
            finding("/vulnerabilities/sqli/", "id", "GET", "GET /vulnerabilities/"),
            "id=probe-value",
        ),
    ],
    ids=["get-keeps-sibling-fields", "get-without-stored-request", "not-a-curl-line"],
)
def test_get_query_keeps_stored_siblings(found: Finding, query: str) -> None:
    method, built, content, headers = build_request(found, BASE, VALUE)
    assert (method, content, headers) == ("GET", None, {})
    assert urlsplit(built).query == query


def form_page(request: requests.PreparedRequest) -> Reply:
    """Like DVWA: a request without ``Submit`` gets the bare form."""
    raw = request.body.decode() if isinstance(request.body, bytes) else request.body
    fields = parse_qs(urlsplit(request.url or "").query) | parse_qs(raw or "")
    if "Submit" not in fields:
        return html(b"<form></form>")
    return html(f"<p>{fields['name'][0]}</p>".encode())


@pytest.mark.parametrize(
    ("method", "stored", "tier", "requests_sent"),
    [
        ("POST", f'curl "{FORM_URL}" -d "name=x&Submit=Go"', T.REPLAY_VERIFIED, 2),
        ("GET", f'curl "{FORM_URL}?name=x&Submit=Go"', T.REPLAY_VERIFIED, 2),
        ("POST", "", T.UNVERIFIED, 2),
    ],
    ids=["post-with-stored-request", "get-with-stored-request", "no-stored-request"],
)
def test_replay_sends_the_stored_fields(
    method: str, stored: str, tier: VerificationTier, requests_sent: int
) -> None:
    """Scenario: Replay keeps sibling fields."""
    scope = Scope(rate_limit_rps=1000.0, allowed_methods=["GET", "POST"])
    net = site({"/form": form_page}, scope=scope)
    xss = case("Cross Site Scripting", FORM_URL, parameter="name", method=method)
    xss.canonical.request_example = stored
    replay([xss], net.client, fast_settings())
    assert xss.canonical.verification.tier == tier
    assert len(net.sent) == requests_sent


@pytest.mark.parametrize(
    ("encoded", "tier"),
    [(False, T.REPLAY_VERIFIED), (True, T.UNVERIFIED)],
    ids=["tag-closes-script", "angle-brackets-encoded"],
)
def test_reflection_in_script_context_needs_a_live_marker(
    encoded: bool, tier: VerificationTier
) -> None:
    """Scenario: Script-context reflection."""

    def script_page(request: requests.PreparedRequest) -> Reply:
        value = parse_qs(urlsplit(request.url or "").query)["q"][0]
        value = escape(value) if encoded else value
        return html(f'<script>var q = "{value}";</script>'.encode())

    net = site({"/script": script_page})
    xss = case("Cross Site Scripting", "https://example.com/script?q=x")
    replay([xss], net.client, fast_settings())
    assert xss.canonical.verification.tier == tier
