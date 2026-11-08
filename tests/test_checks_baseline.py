from urllib.parse import urlsplit

import pytest
import requests
from requests.structures import CaseInsensitiveDict

from haris.checks.baseline import (
    HostClass,
    ResponseFingerprint,
    fingerprint,
    get_baseline,
    matches,
)
from haris.checks.findings import prior
from haris.checks.info_disclosure import InfoDisclosureScanner
from haris.checks.misc_checks import SENSITIVE_PATHS, MiscCheckScanner
from haris.models import Confidence, Severity
from haris.net import ScopedResponse

from .checks_support import (
    HTML_SHELL,
    NOT_FOUND,
    SENSITIVE_PATHS_COUNT,
    html,
    local_site,
    run_check,
    site,
    titles,
)
from .fake_transport import FakeNet

ENV_BODY = b"APP_ENV=production\nDB_PASSWORD=hunter2\nSECRET_KEY=abc123\n"
GIT_CONFIG = b"[core]\n\trepositoryformatversion = 0\n\tbare = false\n"
BLOCK_PAGE = (
    b"<html><head><title>Access Denied</title></head><body>"
    b"Request blocked by security policy. Reference ID: 7731904522</body></html>"
)


def response(body: bytes = b"", status: int = 200, **headers: str) -> ScopedResponse:
    headers.setdefault("Content-Type", "text/html")
    return ScopedResponse(
        status_code=status,
        url="https://example.com/x",
        headers=CaseInsensitiveDict(headers),
        content=body,
    )


def path_findings(net: FakeNet) -> list[str]:
    misc = MiscCheckScanner({"check_cors": False, "check_redirect": False})
    return titles(run_check(misc, net).findings) + titles(
        run_check(InfoDisclosureScanner(), net).findings
    )


def spa(path: str) -> tuple[int, dict[str, str], bytes]:
    page = HTML_SHELL.replace(b"<div", f"<!-- {path} 20241108 --><div".encode())
    return 200, {"Content-Type": "text/html"}, page


def test_spa_catch_all_server_yields_no_path_findings():
    """Scenario: an SPA answering 200 with one shell for every path."""
    with local_site(spa) as client:
        misc = MiscCheckScanner()
        info = InfoDisclosureScanner()
        findings = run_check(misc, client).findings + run_check(info, client).findings
        probed = {urlsplit(e.url).path for e in client.log.entries()}

    assert not [
        f for f in findings if f.vuln_class in {"sensitive_file", "version_disclosure"}
    ]
    assert {p for p, _ in SENSITIVE_PATHS} <= probed
    assert len(SENSITIVE_PATHS) == SENSITIVE_PATHS_COUNT


@pytest.mark.parametrize(
    "block",
    [
        pytest.param(
            lambda _req: (403, {"Content-Type": "text/html"}, BLOCK_PAGE), id="403"
        ),
        pytest.param(lambda _req: html(BLOCK_PAGE), id="200-everywhere"),
    ],
)
def test_waf_block_page_yields_no_path_findings(block):
    assert path_findings(site(fallback=block)) == []


def test_waf_blocking_only_probed_paths_yields_no_path_findings():
    """A WAF serving one generic block page for probed paths and 404 elsewhere."""
    net = site({path: html(BLOCK_PAGE) for path, _ in SENSITIVE_PATHS})
    assert [t for t in path_findings(net) if "sensitive path" in t] == []


def test_real_env_file_is_a_critical_validated_finding_without_leaking_values():
    net = site({"/.env": (200, {"Content-Type": "text/plain"}, ENV_BODY)})
    result = run_check(MiscCheckScanner(), net)

    [found] = [f for f in result.findings if f.title.endswith("/.env")]
    assert found.severity is Severity.CRITICAL
    assert found.confidence_score == prior("misc_checks.sensitive_path_validated")
    assert found.confidence is Confidence.CONFIRMED
    assert found.vuln_class == "sensitive_file"
    assert "hunter2" not in found.evidence + found.description
    assert "APP_ENV=" in found.evidence


def test_real_env_file_is_reported_on_a_catch_all_host():
    net = site(
        {"/.env": (200, {"Content-Type": "text/plain"}, ENV_BODY)}, fallback=html()
    )
    findings = run_check(MiscCheckScanner(), net).findings
    assert [f.title for f in findings if "sensitive" in f.title] == [
        "Accessible sensitive path: /.env"
    ]


def test_env_path_returning_html_is_not_a_finding():
    net = site(
        {"/.env": html(b"<html><title>Login</title><body>Sign in</body></html>")}
    )
    assert path_findings(net) == []


def test_real_git_config_is_reported_and_one_without_core_is_not():
    real = site({"/.git/config": (200, {"Content-Type": "text/plain"}, GIT_CONFIG)})
    fake = site({"/.git/config": (200, {"Content-Type": "text/plain"}, b"hello world")})
    assert "Accessible sensitive path: /.git/config" in path_findings(real)
    assert path_findings(fake) == []


def test_unvalidated_path_on_normal_host_is_tentative_and_ignored_on_catch_all():
    page = html(b"<html><title>Admin</title><body>Dashboard 1</body></html>")
    normal = run_check(MiscCheckScanner(), site({"/admin": page}))
    [found] = [f for f in normal.findings if f.title.endswith("/admin")]
    assert found.confidence_score == prior("misc_checks.sensitive_path")
    assert found.confidence is Confidence.TENTATIVE

    catch_all = site({"/admin": page}, fallback=html())
    assert not [
        f
        for f in run_check(MiscCheckScanner(), catch_all).findings
        if "sensitive" in f.title
    ]


def test_redirected_probe_is_not_the_resource():
    def to_login(_req: requests.PreparedRequest):
        return 302, {"Location": "/login"}, b""

    net = site({"/admin": to_login, "/login": html(b"<title>Login</title>")})
    assert path_findings(net) == []


def test_findings_use_the_one_scan_client():
    net = site({"/.env": (200, {}, ENV_BODY)})
    run_check(MiscCheckScanner(), net)
    logged = {e.url for e in net.client.log.entries()}
    assert "https://example.com/.env" in logged


@pytest.mark.parametrize(
    ("body", "path", "expected"),
    [
        (b"not found: /admin 1234567", "/admin", b"not found:"),
        (b"token AbCdEfGhIjKlMnOpQr here", "/x", b"token here"),
        (b"a   b\n\tc", "/x", b"a b c"),
    ],
)
def test_fingerprint_scrubs_path_numbers_tokens_and_whitespace(body, path, expected):
    plain = fingerprint(response(expected), "/other")
    assert fingerprint(response(body), path).body_hash == plain.body_hash


def test_fingerprint_reads_media_type_title_and_length_bucket():
    fp = fingerprint(
        response(
            b"<TITLE>\n My  App </TITLE>" + b"x" * 1100,
            **{"Content-Type": "Text/HTML; charset=utf-8"},
        ),
        "/p",
    )
    assert (fp.content_type, fp.title, fp.length_bucket) == ("text/html", "my app", 2)


def make_fp(**fields: object) -> ResponseFingerprint:
    base = {
        "status": 200,
        "content_type": "text/html",
        "length": 1000,
        "length_bucket": 1,
        "body_hash": "a",
        "title": "app",
        "location": "",
    }
    return ResponseFingerprint.model_validate(base | fields)


@pytest.mark.parametrize(
    ("probe", "control", "expected"),
    [
        ({}, {}, True),
        ({"status": 404}, {}, False),
        ({"content_type": "application/json"}, {}, False),
        ({"body_hash": "b", "length": 1040}, {}, True),  # same title, within 5%
        ({"body_hash": "b", "length": 1100}, {}, False),  # same title, too long
        ({"body_hash": "b", "title": "other"}, {}, False),
        ({"body_hash": "b", "length": 30}, {"length": 60}, True),  # 64-byte floor
        (
            {"status": 302, "location": "/login"},
            {"status": 302, "location": "/login"},
            True,
        ),
        ({"status": 302, "location": "/a"}, {"status": 302, "location": "/b"}, False),
    ],
)
def test_similarity_rule(probe, control, expected):
    assert matches(make_fp(**probe), make_fp(**control)) is expected


@pytest.mark.parametrize(
    ("fallback", "expected"),
    [
        (html(), HostClass.CATCH_ALL),
        (NOT_FOUND, HostClass.NORMAL),
    ],
)
def test_host_class_from_controls(fallback, expected):
    net = site(fallback=fallback)
    assert get_baseline(net.client, net.client.target.base_url).host_class() is expected


def test_host_class_is_unstable_when_controls_disagree():
    net = site(fallback=NOT_FOUND)
    net.adapter.handler = lambda req: (
        html() if req.url and req.url.endswith(".html") else (404, {}, b"no")
    )
    baseline = get_baseline(net.client, net.client.target.base_url)
    assert baseline.host_class() is HostClass.UNSTABLE


def test_controls_are_fetched_once_per_scan_and_extra_controls_are_capped():
    net = site()
    baseline = get_baseline(net.client, "https://example.com")
    assert get_baseline(net.client, "https://example.com/x") is baseline
    for i in range(15):
        baseline.judge(f"/d{i}/file.php", response(b"found", 200))
    controls = [r.url for r in net.sent]
    assert (
        len(controls) == 3 + 10
    )  # three root controls, at most ten directory controls
