import pytest

from haris.ai_security.discovery import discover

from .ai_support import local_client, scope_with_post
from .checks_support import html, site
from .sse_support import ENDPOINT_EVENT, hanging_sse_server

EVENT_STREAM_TYPE = {"Content-Type": "text/event-stream"}


def found_ids(net) -> set[str]:
    return {e.signature.id for e in discover(net.client, net.client.target)}


def test_event_stream_with_endpoint_event_yields_mcp_sse() -> None:
    net = site(
        {"/sse": (200, EVENT_STREAM_TYPE, ENDPOINT_EVENT)}, scope=scope_with_post()
    )
    assert found_ids(net) == {"mcp_sse"}


def test_sse_is_probed_with_get_not_head() -> None:
    net = site(
        {"/sse": (200, EVENT_STREAM_TYPE, ENDPOINT_EVENT)}, scope=scope_with_post()
    )
    found_ids(net)
    assert [r.method for r in net.sent if "/sse" in (r.url or "")] == ["GET"]


@pytest.mark.parametrize(
    "reply",
    [
        html(b"<html>sse</html>"),
        (200, EVENT_STREAM_TYPE, b"data: hello\n\n"),
        (200, {"Content-Type": "text/plain"}, ENDPOINT_EVENT),
    ],
    ids=["html", "event-stream-without-endpoint", "endpoint-text-not-event-stream"],
)
def test_non_matching_sse_reply_yields_nothing(reply) -> None:
    net = site({"/sse": reply}, scope=scope_with_post())
    assert found_ids(net) == set()


def test_open_event_stream_is_discovered_without_waiting_for_it_to_close() -> None:
    with hanging_sse_server() as base_url, local_client(base_url) as client:
        endpoints = discover(client, client.target)
    assert {e.signature.id for e in endpoints} == {"mcp_sse"}
