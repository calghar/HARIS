from urllib.parse import parse_qs, urlsplit

import pytest
import requests

from haris.agent.models import PoC, PoCRequest
from haris.agent.validator import apply_validation, reexecute
from haris.models import Scope, VerificationTier
from haris.net import ScopedResponse
from haris.verify import load_verify_settings
from haris.verify.probe import Prober
from haris.verify.replay import replay
from tests.checks_support import html, site
from tests.fake_transport import FakeNet, Reply
from tests.verify_server import case, fast_settings, make_client, serve

T = VerificationTier
SEARCH = "/search?q={marker}"  # reflects the marker raw: oracle-positive
ENCODED = "/encoded?q={marker}"  # reflects it HTML-encoded: inconclusive
POC_REQUESTS = 15
POC_SENDS = 20


def xss_poc(base: str, paths: list[str]) -> PoC:
    return PoC(
        requests=[PoCRequest(url=f"{base}{p}") for p in paths], oracle="reflection"
    )


@pytest.mark.parametrize(
    ("paths", "tier"),
    [
        ([SEARCH, SEARCH, SEARCH], T.EXPLOIT_VALIDATED),
        ([SEARCH, ENCODED, ENCODED], T.EXPLOIT_VALIDATED),
        ([ENCODED, SEARCH, ENCODED], T.EXPLOIT_VALIDATED),
        ([ENCODED, ENCODED, ENCODED], T.REPLAY_VERIFIED),
    ],
    ids=["all-positive", "first-positive", "middle-positive", "none-positive"],
)
def test_several_poc_requests_decide_the_tier(
    paths: list[str], tier: VerificationTier
) -> None:
    """Scenario: Several PoC requests."""
    with serve() as fx:
        finding = case("Cross Site Scripting", f"{fx.url}/search?q=1")
        finding.canonical.verification.advance(T.REPLAY_VERIFIED)
        with make_client(fx.url) as client:
            apply_validation(
                finding,
                xss_poc(fx.url, paths),
                client,
                model="fake-agent",
                allow_unsafe=False,
            )
    sent = [path.split("?")[0] for _, path in fx.seen]
    assert finding.canonical.verification.tier == tier
    assert sent == [p.split("?")[0] for p in paths for _ in range(2)]


def test_poc_request_cap_sends_ten_requests_each_followed_by_its_control() -> None:
    """Scenario: PoC request cap."""
    assert load_verify_settings().poc_max_requests == POC_SENDS
    with serve() as fx:
        finding = case("Cross Site Scripting", f"{fx.url}/search?q=1")
        poc = xss_poc(fx.url, [f"{SEARCH}&n={i}" for i in range(POC_REQUESTS)])
        with make_client(fx.url) as client:
            apply_validation(
                finding, poc, client, model="fake-agent", allow_unsafe=False
            )
            sent_total = client.requests_sent
    numbers = [parse_qs(urlsplit(path).query)["n"][0] for _, path in fx.seen]
    marked = ["haris" in path for _, path in fx.seen]
    assert sent_total == len(fx.seen) == POC_SENDS
    assert numbers == [str(i // 2) for i in range(POC_SENDS)]
    assert marked == [i % 2 == 0 for i in range(POC_SENDS)]


def reflecting(request: requests.PreparedRequest) -> Reply:
    value = parse_qs(urlsplit(request.url or "").query).get("q", [""])[0]
    body = f"<html><body>You searched: {value}</body></html>".encode()
    return 200, {"Content-Type": "text/html"}, body


@pytest.mark.parametrize("rps", [5, 20])
def test_poc_sends_are_spaced_by_the_scope_rate_limit(rps: int) -> None:
    """Scenario: PoC rate limit."""
    net = FakeNet(reflecting, scope=Scope(rate_limit_rps=rps))
    finding = case("Cross Site Scripting", "https://example.com/search?q=1")
    poc = xss_poc("https://example.com", [SEARCH] * 10)
    burst = net.client._bucket._capacity
    found, exchanges = reexecute(
        poc, finding, Prober(net.client, POC_SENDS), allow_unsafe=False
    )
    assert found is True
    assert len(net.sent) == len(exchanges) == POC_SENDS
    assert net.clock.now - 1000.0 == pytest.approx((POC_SENDS - burst) / rps)
    assert net.clock.sleeps == [pytest.approx(1 / rps)] * (POC_SENDS - burst)


def test_replay_controls_use_the_request_timeout_not_the_policy_timeout() -> None:
    """Scenario: Control timeout."""
    net = site(fallback=html())
    client = net.client
    original = client._send
    seen: list[tuple[str, float]] = []

    def spy(
        method: str,
        url: str,
        vetted: tuple[str, int, str],
        headers: dict[str, str] | None,
        body: bytes | str | None,
        timeout: float,
        stream_bytes: int | None,
    ) -> ScopedResponse:
        seen.append((url, timeout))
        return original(method, url, vetted, headers, body, timeout, stream_bytes)

    client._send = spy  # type: ignore[method-assign]  # records the effective timeout
    finding = case(
        "This might be interesting.",
        "https://example.com/.psql_history",
        scanner="nikto",
        parameter="",
    )
    replay([finding], client, fast_settings(request_timeout_s=10.0))
    controls = [timeout for url, timeout in seen if "/haris-" in url]
    assert client.policy.timeout_s == 30.0
    assert len(controls) >= 3
    assert {timeout for _, timeout in seen} == {10.0}
