import io
import time
from typing import Any

import pytest
import requests
import urllib3
from requests.structures import CaseInsensitiveDict

from haris.models import AuthConfig, Finding, Scope, Severity
from haris.net import (
    NetworkPolicy,
    RequestBudgetExceeded,
    ScopeViolation,
    SSRFBlocked,
)
from haris.verify.probe import Prober

from .ai_support import local_client
from .fake_transport import FakeAdapter, FakeNet, Handler, ok
from .sse_support import ENDPOINT_EVENT, hanging_sse_server

URL = "https://example.com/stream"
POLICY_TIMEOUT_S = NetworkPolicy().timeout_s
BIG_BODY = b"x" * 10_000


class RecordingAdapter(FakeAdapter):
    """Records the transport timeout; ``live`` serves a socket-style raw body."""

    def __init__(self, handler: Handler, *, live: bool = False) -> None:
        super().__init__(handler)
        self.timeouts: list[object] = []
        self.live = live

    def send(  # type: ignore[override]  # fake ignores the transport options
        self, request: requests.PreparedRequest, **options: Any
    ) -> requests.Response:
        self.timeouts.append(options.get("timeout"))
        response = super().send(request, **options)
        if self.live:
            raw = urllib3.HTTPResponse(
                body=io.BytesIO(response._content),  # type: ignore[arg-type]  # bytes after fake read
                preload_content=False,
                headers=dict(response.headers),
                status=response.status_code,
            )
            response = requests.Response()
            response.status_code = raw.status
            response.headers = CaseInsensitiveDict(raw.headers)
            response.raw = raw
        return response


def fake_net(
    handler: Handler | None = None, *, live: bool = False, **kwargs: Any
) -> tuple[FakeNet, RecordingAdapter]:
    net = FakeNet(handler, **kwargs)
    adapter = RecordingAdapter(net.adapter.handler, live=live)
    net.adapter = adapter
    return net, adapter


class TestPerCallTimeout:
    @pytest.mark.parametrize(
        ("call_timeout", "expected"),
        [
            (5.0, 5.0),
            (None, POLICY_TIMEOUT_S),
            (POLICY_TIMEOUT_S * 4, POLICY_TIMEOUT_S),
        ],
        ids=["tighter", "absent", "never-above-policy"],
    )
    def test_timeout_reaches_the_transport_capped_by_policy(
        self, call_timeout: float | None, expected: float
    ) -> None:
        net, adapter = fake_net()
        net.client.request("GET", URL, timeout_s=call_timeout)
        assert adapter.timeouts == [expected]

    def test_policy_object_is_unchanged_after_a_call(self) -> None:
        net, _ = fake_net()
        before = net.client.policy.model_copy()
        net.client.request("GET", URL, timeout_s=1.0)
        net.client.stream(URL, timeout_s=1.0)
        assert net.client.policy == before


class TestProberTimeout:
    def test_requests_carry_the_cap_and_leave_the_policy_timeout_alone(self) -> None:
        net, adapter = fake_net()
        Prober(net.client, 10, timeout_s=2.0).request("GET", URL)
        assert net.client.policy.timeout_s == POLICY_TIMEOUT_S
        assert adapter.timeouts == [2.0]

    def test_prober_without_timeout_uses_the_policy_timeout(self) -> None:
        net, adapter = fake_net()
        Prober(net.client, 10).request("GET", URL)
        assert adapter.timeouts == [POLICY_TIMEOUT_S]

    def test_prober_send_keeps_the_per_call_timeout(self) -> None:
        net, adapter = fake_net()
        finding = Finding(
            title="Cross Site Scripting",
            description="",
            severity=Severity.HIGH,
            url="/s?q=1",
            parameter="q",
            scanner="wapiti",
        )
        Prober(net.client, 10, timeout_s=3.0).send(finding, "v")
        assert adapter.timeouts == [3.0]


@pytest.mark.parametrize("live", [False, True], ids=["iter_content", "read1"])
class TestBoundedRead:
    def test_stops_at_max_bytes_and_flags_truncation(self, live: bool) -> None:
        net, _ = fake_net(lambda _r: ok(BIG_BODY), live=live)
        response = net.client.stream(URL, max_bytes=100)
        assert response.content == BIG_BODY[:100]
        assert response.truncated is True

    @pytest.mark.parametrize("size", [99, 100], ids=["below", "exactly-max"])
    def test_body_within_max_bytes_is_not_truncated(
        self, live: bool, size: int
    ) -> None:
        net, _ = fake_net(lambda _r: ok(BIG_BODY[:size]), live=live)
        response = net.client.stream(URL, max_bytes=100)
        assert len(response.content) == size
        assert response.truncated is False

    def test_log_entry_holds_the_excerpt_only(self, live: bool) -> None:
        net, _ = fake_net(lambda _r: ok(BIG_BODY), live=live)
        net.client.stream(URL, max_bytes=100)
        assert net.client.log.entries()[0].response_body_excerpt == "x" * 100


class TestStreamKeepsEveryGuard:
    def test_out_of_scope_host_raises_before_any_byte(self) -> None:
        net, _ = fake_net()
        with pytest.raises(ScopeViolation):
            net.client.stream("https://evil.test/sse")
        assert net.sent == []

    def test_ssrf_blocked_host_raises_before_any_byte(self) -> None:
        net, _ = fake_net(resolves={"example.com": ["10.0.0.5"]})
        with pytest.raises(SSRFBlocked):
            net.client.stream(URL)
        assert net.sent == []

    def test_streamed_requests_count_toward_the_request_cap(self) -> None:
        net, _ = fake_net(scope=Scope(max_requests=2, rate_limit_rps=1000.0))
        net.client.stream(URL)
        net.client.stream(URL)
        with pytest.raises(RequestBudgetExceeded):
            net.client.stream(URL)
        assert len(net.sent) == net.client.requests_sent == 2

    def test_streamed_requests_are_rate_limited(self) -> None:
        net, _ = fake_net(scope=Scope(rate_limit_rps=2.0))
        start = net.clock()
        for _ in range(10):
            net.client.stream(URL)
        assert net.clock() - start >= 4.0

    def test_method_outside_scope_is_refused(self) -> None:
        net, _ = fake_net(scope=Scope(allowed_methods=["HEAD"], rate_limit_rps=1000.0))
        with pytest.raises(ScopeViolation, match="GET"):
            net.client.stream(URL)
        assert net.sent == []

    def test_redirect_hop_out_of_scope_ends_the_chain(self) -> None:
        net, _ = fake_net(lambda _r: (302, {"Location": "https://evil.test/x"}, b""))
        response = net.client.stream(URL)
        assert response.redirect_blocked is True
        assert len(net.sent) == 1

    def test_log_entry_is_redacted(self) -> None:
        net, _ = fake_net(
            lambda _r: (200, {"Set-Cookie": "sid=xyz"}, b"data"),
            auth=AuthConfig(method="header", header_value="Bearer abc123"),
        )
        net.client.stream(URL)
        dumped = net.client.log.entries()[0].model_dump_json()
        assert "[REDACTED]" in dumped
        assert "abc123" not in dumped
        assert "xyz" not in dumped


class TestLiveSocket:
    def test_open_stream_returns_the_bytes_read_when_the_timeout_hits(self) -> None:
        with hanging_sse_server() as base_url, local_client(base_url) as client:
            started = time.monotonic()
            response = client.stream(f"{base_url}/sse", max_bytes=4096, timeout_s=0.5)
        assert response.content == ENDPOINT_EVENT
        assert response.truncated is True
        assert time.monotonic() - started < 5.0
