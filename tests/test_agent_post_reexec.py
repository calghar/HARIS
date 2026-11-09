import http.server
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from urllib.parse import parse_qs, unquote_plus

import pytest

from haris.agent.models import PoC, PoCRequest
from haris.agent.validator import apply_validation, reexecute
from haris.models import (
    CorrelatedFinding,
    Scope,
    Target,
    VerificationMethod,
    VerificationTier,
)
from haris.net import NetworkPolicy, ScopedClient
from haris.verify.probe import Prober
from tests.agent_support import finding as make_finding

SPAN = "model-chosen-span"


@dataclass
class Seen:
    requests: list[tuple[str, dict[str, str], str]] = field(default_factory=list)


class _Page(http.server.BaseHTTPRequestHandler):
    escape = False
    seen = Seen()

    def _reply(self, value: str) -> None:
        if self.escape:
            value = value.replace("<", "&lt;").replace(">", "&gt;")
        body = f"<html><body>You searched: {value}</body></html>".encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self) -> None:
        raw = self.rfile.read(int(self.headers.get("Content-Length", "0"))).decode()
        headers = {key.lower(): value for key, value in self.headers.items()}
        self.seen.requests.append(("POST", headers, raw))
        self._reply(parse_qs(raw).get("q", [""])[0])

    def do_GET(self) -> None:
        self.seen.requests.append(("GET", {}, self.path))
        self._reply("")

    def log_message(self, *_args: object) -> None:
        return None


@contextmanager
def _serve(*, escape: bool = False) -> Iterator[tuple[str, Seen]]:
    seen = Seen()
    handler = type("H", (_Page,), {"escape": escape, "seen": seen})
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}", seen
    finally:
        server.shutdown()
        server.server_close()


def _case(
    base: str, finding_url: str | None = None
) -> tuple[CorrelatedFinding, ScopedClient]:
    item = make_finding(finding_url or f"{base}/search").model_copy(
        update={"method": "POST"}
    )
    target = Target(
        base_url=base,
        scope=Scope(
            rate_limit_rps=1000,
            max_requests=100,
            allowed_methods=["GET", "HEAD", "OPTIONS", "POST"],
        ),
    )
    client = ScopedClient(target, NetworkPolicy(allow_private=True))
    return CorrelatedFinding(canonical=item, consensus_score=0.5), client


def _poc(url: str, body: str) -> PoC:
    return PoC(
        requests=[PoCRequest(method="POST", url=url, body=body)],
        oracle="reflection",
        expected_span=SPAN,
    )


def test_post_body_marker_is_confirmed_with_a_form_request():
    """Scenario: POST finding replayed with the fresh marker in the form body."""
    with _serve() as (base, seen):
        case, client = _case(base)
        positive, exchanges = reexecute(
            _poc(f"{base}/search", "q={marker}"),
            case,
            Prober(client, 8),
            allow_unsafe=True,
        )
        client.close()
    assert positive is True
    assert [e.role for e in exchanges] == ["poc", "control"]
    assert [e.method for e in exchanges] == ["POST", "POST"]
    assert len(seen.requests) == 2
    method, headers, raw = seen.requests[0]
    assert method == "POST"
    assert headers["content-type"] == "application/x-www-form-urlencoded"
    sent = unquote_plus(raw.removeprefix("q="))
    assert "{marker}" not in raw
    assert SPAN not in raw
    assert sent.startswith("\"'><")
    assert exchanges[0].request_body_excerpt.startswith("q=")


def test_post_is_not_sent_without_allow_unsafe():
    """Scenario: POST PoC without the unsafe-methods opt-in."""
    with _serve() as (base, seen):
        case, client = _case(base)
        positive, exchanges = reexecute(
            _poc(f"{base}/search", "q={marker}"),
            case,
            Prober(client, 8),
            allow_unsafe=False,
        )
        client.close()
    assert (positive, exchanges) == (False, [])
    assert seen.requests == []


def test_post_to_another_url_is_not_sent():
    """Scenario: POST PoC whose URL differs from the finding's URL."""
    with _serve() as (base, seen):
        case, client = _case(base)
        positive, _ = reexecute(
            _poc(f"{base}/other", "q={marker}"),
            case,
            Prober(client, 8),
            allow_unsafe=True,
        )
        client.close()
    assert positive is False
    assert seen.requests == []


def test_post_with_marker_in_the_url_is_not_sent():
    """Scenario: POST PoC that moves the placeholder into the URL."""
    with _serve() as (base, seen):
        case, client = _case(base)
        positive, _ = reexecute(
            _poc(f"{base}/search?q={{marker}}", ""),
            case,
            Prober(client, 8),
            allow_unsafe=True,
        )
        client.close()
    assert positive is False
    assert seen.requests == []


@pytest.mark.parametrize(
    "body",
    [
        "id=1;DROP TABLE users&q={marker}",
        "id=1; select pg_sleep(30)&q={marker}",
        "q={marker}&n=sleep(60)",
    ],
)
def test_destructive_post_body_is_not_sent(body: str):
    """Scenario: PoC body matching the destructive SQL or long-sleep rule."""
    with _serve() as (base, seen):
        case, client = _case(base)
        positive, _ = reexecute(
            _poc(f"{base}/search", body),
            case,
            Prober(client, 8),
            allow_unsafe=True,
        )
        client.close()
    assert positive is False
    assert seen.requests == []


@pytest.mark.parametrize(
    "body",
    [
        "id=1%3BDROP%20TABLE%20users&q={marker}",
        "q={marker}&n=sleep%2815%29",
        "id=1%253BDROP%2520TABLE%2520users&q={marker}",
    ],
    ids=["encoded-drop", "encoded-sleep", "double-encoded-drop"],
)
def test_percent_encoded_destructive_body_is_not_sent(body: str):
    """Scenario: destructive content hidden by percent-encoding."""
    with _serve() as (base, seen):
        case, client = _case(base)
        positive, _ = reexecute(
            _poc(f"{base}/search", body),
            case,
            Prober(client, 8),
            allow_unsafe=True,
        )
        client.close()
    assert positive is False
    assert seen.requests == []


def test_relative_finding_url_accepts_the_same_absolute_poc_url():
    """Scenario: relative finding URL, absolute PoC URL on the same path."""
    with _serve() as (base, seen):
        case, client = _case(base, "/search")
        positive, _ = reexecute(
            _poc(f"{base}/search", "q={marker}"),
            case,
            Prober(client, 8),
            allow_unsafe=True,
        )
        client.close()
    assert positive is True
    assert [method for method, _, _ in seen.requests] == ["POST", "POST"]


def test_relative_finding_url_rejects_a_different_path():
    """Scenario: relative finding URL, PoC URL on another path."""
    with _serve() as (base, seen):
        case, client = _case(base, "/search")
        positive, _ = reexecute(
            _poc(f"{base}/other", "q={marker}"),
            case,
            Prober(client, 8),
            allow_unsafe=True,
        )
        client.close()
    assert positive is False
    assert seen.requests == []


def test_encoded_post_reflection_is_not_positive():
    """Scenario: server HTML-encodes the reflected form value."""
    with _serve(escape=True) as (base, seen):
        case, client = _case(base)
        positive, exchanges = reexecute(
            _poc(f"{base}/search", "q={marker}"),
            case,
            Prober(client, 8),
            allow_unsafe=True,
        )
        client.close()
    assert positive is False
    assert len(exchanges) == 2
    assert len(seen.requests) == 2


def test_post_finding_reaches_exploit_validated():
    """Scenario: apply_validation moves a POST finding to exploit_validated."""
    with _serve() as (base, _seen):
        case, client = _case(base)
        note = apply_validation(
            case,
            _poc(f"{base}/search", "q={marker}"),
            client,
            model="fake-agent",
            allow_unsafe=True,
        )
        client.close()
    verification = case.canonical.verification
    assert note == ""
    assert verification.tier is VerificationTier.EXPLOIT_VALIDATED
    assert verification.method is VerificationMethod.AGENT
    assert [e.role for e in verification.evidence] == ["poc", "control"]
