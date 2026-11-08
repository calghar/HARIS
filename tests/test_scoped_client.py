import http.server
import logging
import shutil
import subprocess
import sys
import threading
from pathlib import Path

import pytest
import requests

from haris.models import AuthConfig, Scope, Target
from haris.net import (
    NetworkPolicy,
    RequestBudgetExceeded,
    ScopedClient,
    ScopeViolation,
    SSRFBlocked,
    TransportError,
)
from haris.net.transport import PinnedAdapter

from .fake_transport import FakeNet, ok

FIXTURES = Path(__file__).parent / "fixtures"


def redirecting(chain: dict[str, str]):
    """Handler: ``chain`` maps a URL path-or-URL to the Location it redirects to."""

    def handler(request: requests.PreparedRequest):
        path = request.url.split(":443", 1)[-1] if request.url else ""
        host = request.headers["Host"]
        key = f"https://{host}{path}"
        if key in chain:
            return 302, {"Location": chain[key]}, b""
        return ok()

    return handler


@pytest.mark.parametrize(
    ("chain", "sent", "blocked"),
    [
        ({"https://example.com/start": "https://www.example.com/a"}, 2, False),
        ({"https://example.com/start": "https://evil.test/a"}, 1, True),
        ({"https://example.com/start": "https://example.com/admin/x"}, 1, True),
        ({"https://example.com/start": "ftp://example.com/a"}, 1, True),
        (
            {
                "https://example.com/start": "https://example.com/a",
                "https://example.com/a": "https://example.com/b",
                "https://example.com/b": "https://example.com/c",
            },
            3,
            True,
        ),
        (
            {"https://example.com/start": "http://169.254.169.254/latest/meta-data"},
            1,
            True,
        ),
    ],
)
def test_redirect_hop_matrix(chain, sent, blocked):
    """Scenario: Redirect hop matrix."""
    scope = Scope(
        allowed_domains=["example.com"],
        excluded_paths=["^/admin"],
        max_redirect_depth=2,
        rate_limit_rps=1000.0,
    )
    net = FakeNet(redirecting(chain), scope=scope)
    response = net.client.get("https://example.com/start")

    assert len(net.sent) == sent
    assert response.redirect_blocked is blocked


def test_redirects_are_not_followed_when_scope_disables_them():
    scope = Scope(follow_redirects=False, rate_limit_rps=1000.0)
    net = FakeNet(
        redirecting({"https://example.com/start": "https://example.com/a"}), scope=scope
    )
    response = net.client.get("https://example.com/start")
    assert response.status_code == 302
    assert not response.redirect_blocked
    assert len(net.sent) == 1


def test_redirect_303_switches_post_to_get_and_drops_body():
    scope = Scope(allowed_methods=["GET", "POST"], rate_limit_rps=1000.0)
    net = FakeNet(
        redirecting({"https://example.com/form": "https://example.com/done"}),
        scope=scope,
    )
    net.client.request("POST", "https://example.com/form", body=b"a=1")
    assert [r.method for r in net.sent] == ["POST", "GET"]
    assert net.sent[1].body is None


def test_method_outside_scope_raises_and_sends_nothing():
    """Scenario: Method outside scope."""
    net = FakeNet(scope=Scope(allowed_methods=["GET", "HEAD", "OPTIONS"]))
    with pytest.raises(ScopeViolation, match="POST"):
        net.client.request("POST", "https://example.com/login")
    assert net.sent == []


@pytest.mark.parametrize(
    "url", ["ftp://example.com/x", "file:///etc/passwd", "https://evil.test/"]
)
def test_scheme_and_domain_are_enforced_before_sending(url):
    net = FakeNet()
    with pytest.raises(ScopeViolation):
        net.client.get(url)
    assert net.sent == []


def test_request_cap_raises_for_the_request_that_would_exceed_it():
    """Scenario: Request cap."""
    net = FakeNet(scope=Scope(max_requests=5, rate_limit_rps=1000.0))
    results = []
    for _ in range(8):
        try:
            results.append(net.client.get("https://example.com/"))
        except RequestBudgetExceeded as exc:
            assert "max_requests=5" in str(exc)
            break
    assert len(net.sent) == 5
    assert len(results) == 5
    assert net.client.budget_exceeded


def test_retries_and_redirect_hops_count_toward_the_cap():
    replies = iter([(503, {}, b""), ok()])
    net = FakeNet(
        lambda _r: next(replies), scope=Scope(max_requests=1, rate_limit_rps=1000.0)
    )
    with pytest.raises(RequestBudgetExceeded):
        net.client.get("https://example.com/")
    assert len(net.sent) == 1


def test_rate_limit_applies_to_the_client():
    """Scenario: Rate limit."""
    net = FakeNet(scope=Scope(rate_limit_rps=2.0))
    start = net.clock()
    sent_at: list[float] = []

    def stamp(_request):
        sent_at.append(net.clock() - start)
        return ok()

    net.adapter.handler = stamp
    for _ in range(10):
        net.client.get("https://example.com/")
    assert sent_at[9] >= 4.0 - 1e-9


@pytest.mark.parametrize(
    ("replies", "sent", "status"),
    [
        ([(200, {})], 1, 200),
        ([(503, {}), (200, {})], 2, 200),
        ([(503, {}), (503, {}), (503, {})], 3, 503),
        ([(404, {})], 1, 404),
        ([(429, {"Retry-After": "1"}), (200, {})], 2, 200),
        ([(429, {}), (429, {}), (429, {})], 3, 429),
    ],
)
def test_retry_outcomes(replies, sent, status):
    """Scenario: Retry outcomes."""
    queue = iter(replies)
    net = FakeNet(lambda _r: (*next(queue), b""))
    response = net.client.get("https://example.com/")
    assert len(net.sent) == sent
    assert response.status_code == status


def test_retry_after_is_honoured_and_capped():
    queue = iter(
        [(429, {"Retry-After": "1"}, b""), (429, {"Retry-After": "900"}, b""), ok()]
    )
    net = FakeNet(lambda _r: next(queue))
    net.client.get("https://example.com/")
    assert net.clock.sleeps == [1.0, 60.0]


def test_backoff_doubles_with_bounded_jitter():
    queue = iter([(503, {}, b""), (503, {}, b""), ok()])
    net = FakeNet(lambda _r: next(queue))
    net.client.get("https://example.com/")
    first, second = net.clock.sleeps
    assert 0.5 <= first < 0.75
    assert 1.0 <= second < 1.25


def test_rate_halves_after_429():
    """Scenario: Rate halves after 429."""
    queue = iter([(429, {"Retry-After": "0"}, b""), ok()])
    net = FakeNet(lambda _r: next(queue), scope=Scope(rate_limit_rps=4.0))
    assert net.client.rate_rps == 4.0
    net.client.get("https://example.com/")
    assert net.client.rate_rps == 2.0


def test_connection_errors_retry_then_raise_transport_error():
    def failing(_request):
        raise requests.ConnectionError("reset")

    net = FakeNet(failing)
    with pytest.raises(TransportError, match="reset"):
        net.client.get("https://example.com/")
    assert len(net.sent) == 3

    calls = iter([requests.ConnectionError("once"), None])

    def flaky(_request):
        err = next(calls)
        if err:
            raise err
        return ok()

    assert FakeNet(flaky).client.get("https://example.com/").status_code == 200


def test_header_redaction_in_log_and_application_logs(caplog):
    """Scenario: Header redaction."""

    def reply(_request):
        return 200, {"Set-Cookie": "sid=xyz; Path=/", "X-Api-Key": "k-999"}, b"body"

    auth = AuthConfig(
        method="header", header_name="Authorization", header_value="Bearer abc123"
    )
    net = FakeNet(reply, auth=auth)
    with caplog.at_level(logging.DEBUG):
        response = net.client.get(
            "https://example.com/", headers={"X-Session-Id": "s-1"}
        )

    assert net.sent[0].headers["Authorization"] == "Bearer abc123"
    entry = net.client.log.get(response.request_id)
    assert entry is not None
    assert entry.request_headers["Authorization"] == "[REDACTED]"
    assert entry.request_headers["X-Session-Id"] == "[REDACTED]"
    assert entry.response_headers["Set-Cookie"] == "[REDACTED]"
    assert entry.response_headers["X-Api-Key"] == "[REDACTED]"
    dumped = entry.model_dump_json() + caplog.text
    for secret in ("abc123", "xyz", "k-999", "s-1"):
        assert secret not in dumped
    assert response.set_cookies == ["sid=xyz; Path=/"]


def test_every_request_is_logged_with_a_usable_evidence_id():
    net = FakeNet(lambda _r: ok(b"x" * 20000))
    first = net.client.get("https://example.com/a")
    second = net.client.get("https://example.com/b")

    assert [e.request_id for e in net.client.log.entries()] == [
        first.request_id,
        second.request_id,
    ]
    exchange = net.client.log.get(first.request_id).to_exchange("baseline")
    assert exchange.role == "baseline"
    assert exchange.request_id == first.request_id
    assert len(exchange.response_body_excerpt) == 8192
    assert len(first.content) == 20000


def test_body_is_capped_by_policy():
    net = FakeNet(lambda _r: ok(b"x" * 100))
    net.client.policy.max_body_bytes = 10
    assert net.client.get("https://example.com/").content == b"x" * 10


def test_session_does_not_replay_target_cookies():
    queue = iter([(200, {"Set-Cookie": "sid=1"}, b""), ok()])
    net = FakeNet(lambda _r: next(queue))
    net.client.get("https://example.com/")
    net.client.get("https://example.com/")
    assert "Cookie" not in net.sent[1].headers


def test_preflight_vets_without_sending():
    net = FakeNet(base_url="https://t.example", resolves={"t.example": ["10.0.0.5"]})
    with pytest.raises(SSRFBlocked, match="blocked"):
        net.client.preflight("https://t.example")
    assert net.sent == []
    assert FakeNet().client.preflight("https://example.com") == "93.184.216.34"


class _Recorder(http.server.BaseHTTPRequestHandler):
    seen: list[str] = []

    def do_GET(self) -> None:
        _Recorder.seen.append(self.headers["Host"])
        body = b"hello"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_args: object) -> None:
        return None


def test_real_pinned_adapter_connects_to_vetted_ip_with_original_host_header():
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _Recorder)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    port = server.server_address[1]
    target = Target(
        base_url=f"http://t.example:{port}", scope=Scope(rate_limit_rps=1000.0)
    )
    try:
        with ScopedClient(
            target,
            NetworkPolicy(allow_private=True),
            resolver=lambda _host, _port: ["127.0.0.1"],
        ) as client:
            response = client.get(f"http://t.example:{port}/x")
    finally:
        server.shutdown()
        server.server_close()

    assert response.content == b"hello"
    assert _Recorder.seen == [f"t.example:{port}"]


def test_pinned_adapter_sets_sni_and_certificate_hostname():
    adapter = PinnedAdapter("t.example")
    kwargs = adapter.poolmanager.connection_pool_kw
    assert kwargs["server_hostname"] == "t.example"
    assert kwargs["assert_hostname"] == "t.example"
    https_pool = adapter.poolmanager.connection_from_url("https://93.184.216.34:443/")
    assert https_pool.assert_hostname == "t.example"
    assert (
        adapter.poolmanager.connection_from_url("http://93.184.216.34:80/").port == 80
    )


def test_direct_http_library_imports_fail_the_lint_gate(tmp_path):
    """Scenario: Direct requests import is rejected."""
    ruff = shutil.which("ruff") or str(Path(sys.executable).with_name("ruff"))
    shutil.copy(FIXTURES / "ruff_scoped_http.toml", tmp_path / "ruff.toml")
    bad = tmp_path / "haris" / "checks" / "new_check.py"
    allowed = tmp_path / "haris" / "net" / "transport_user.py"
    for path in (bad, allowed):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("import requests\n")

    result = subprocess.run(
        [ruff, "check", "--no-cache", "--config", "ruff.toml", "haris"],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode != 0
    assert "haris/checks/new_check.py" in result.stdout
    assert "haris/net/transport_user.py" not in result.stdout
