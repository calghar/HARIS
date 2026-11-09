import http.server
import json
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

import pytest

from haris.agent.models import PoC, PoCRequest
from haris.agent.validator import reexecute
from haris.llm.base import BaseLLMBackend
from haris.models import (
    CorrelatedFinding,
    LLMResponse,
    Scope,
    Target,
    VerificationMethod,
    VerificationTier,
)
from haris.net import NetworkPolicy, ScopedClient
from haris.verify.probe import Prober
from tests.agent_support import (
    ScriptedBackend,
    policy_for,
    run,
    session_for,
)
from tests.agent_support import (
    finding as make_finding,
)


class _Page(http.server.BaseHTTPRequestHandler):
    escape = False

    def do_GET(self) -> None:
        value = parse_qs(urlsplit(self.path).query).get("q", [""])[0]
        if self.escape:
            value = (
                value.replace("&", "&amp;")
                .replace("<", "&lt;")
                .replace(">", "&gt;")
                .replace('"', "&quot;")
            )
        body = f"<html><body>You searched: {value}</body></html>".encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_args: object) -> None:
        return None


@contextmanager
def _serve(*, escape: bool) -> Iterator[str]:
    handler = type("H", (_Page,), {"escape": escape})
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}"
    finally:
        server.shutdown()
        server.server_close()


class Reviewing(BaseLLMBackend):
    """Returns a PoC, and a confirming review that must not decide the tier."""

    name = "reviewing"
    model = "fake-agent"

    def __init__(self, url: str) -> None:
        self.url = url
        self.systems: list[str] = []

    def complete(
        self,
        prompt: str,
        *,
        system: str = "",
        temperature: float = 0.2,
        max_tokens: int = 2048,
    ) -> LLMResponse:
        self.systems.append(system)
        if "no tools" in system:
            text = json.dumps({"notes": "confirmed", "agrees": True})
        else:
            text = json.dumps(
                {
                    "tool": "submit_poc",
                    "arguments": {
                        "url": f"{self.url}/search?q={{marker}}",
                        "oracle": "reflection",
                        "expected_span": "confirmed",
                    },
                    "claim": "exploit succeeded",
                }
            )
        return LLMResponse(
            text=text,
            model=self.model,
            usage={"prompt_tokens": 5, "completion_tokens": 5, "total_tokens": 10},
        )


def test_reflected_marker_is_exploit_validated(tmp_path: Path):
    """Scenario: PoC whose re-execution reflects the fresh marker raw."""
    with _serve(escape=False) as base:
        session, client = session_for(base)
        before = client.requests_sent
        run(session, client, Reviewing(base), policy_for(str(tmp_path)), _runtime())
        finding = session.correlated[0].canonical
        assert finding.verification.tier is VerificationTier.EXPLOIT_VALIDATED
        assert finding.verification.method is VerificationMethod.AGENT
        assert finding.verification.verdict_source.startswith("agent:")
        assert client.requests_sent > before
        client.close()


def test_encoded_marker_keeps_the_tier(tmp_path: Path):
    """Scenario: encoded marker stays replay_verified; review text is ignored."""
    with _serve(escape=True) as base:
        session, client = session_for(base)
        run(session, client, Reviewing(base), policy_for(str(tmp_path)), _runtime())
        finding = session.correlated[0].canonical
        assert finding.verification.tier is VerificationTier.REPLAY_VERIFIED
        assert "not confirmed" in finding.agent_annotation
        client.close()


def test_prose_claim_does_not_change_the_tier(tmp_path: Path):
    """Scenario: text exploit succeeded and no PoC."""
    session, client = session_for("http://127.0.0.1")
    backend = ScriptedBackend([{"done": True, "claim": "exploit succeeded"}])
    run(session, client, backend, policy_for(str(tmp_path)), _runtime())
    finding = session.correlated[0].canonical
    assert finding.verification.tier is VerificationTier.REPLAY_VERIFIED
    assert finding.agent_annotation == "exploit succeeded"
    assert client.requests_sent == 0
    client.close()


def test_out_of_scope_poc_is_not_sent(tmp_path: Path):
    """Scenario: PoC targeting an out-of-scope host."""
    session, client = session_for("http://127.0.0.1")
    backend = ScriptedBackend(
        [
            {
                "tool": "submit_poc",
                "arguments": {
                    "url": "http://evil.test/search?q={marker}",
                    "oracle": "reflection",
                },
            }
        ]
    )
    run(session, client, backend, policy_for(str(tmp_path)), _runtime())
    finding = session.correlated[0].canonical
    assert finding.verification.tier is VerificationTier.REPLAY_VERIFIED
    assert client.requests_sent == 0
    client.close()


POST_ROWS = [
    ("GET", "POST", "/search", "/search", False),
    ("POST", "POST", "/search", "/other", False),
    ("POST", "PUT", "/search", "/search", False),
    ("POST", "DELETE", "/search", "/search", False),
    ("POST", "PATCH", "/search", "/search", False),
    ("POST", "POST", "/search", "/search", True),
]


@pytest.mark.parametrize("observed,sent,found,poc_path,sends", POST_ROWS)
def test_unsafe_method_replays_only_the_observed_post(
    observed: str, sent: str, found: str, poc_path: str, sends: bool
):
    """Scenario: Proxy egress matrix (re-execution path)."""
    with _serve(escape=False) as base:
        item = make_finding(f"{base}{found}").model_copy(update={"method": observed})
        target = Target(
            base_url=base,
            scope=Scope(
                rate_limit_rps=1000,
                max_requests=100,
                allowed_methods=["GET", "HEAD", "OPTIONS", "POST", "PUT", "DELETE"],
            ),
        )
        client = ScopedClient(target, NetworkPolicy(allow_private=True))
        poc = PoC(
            requests=[PoCRequest(method=sent, url=f"{base}{poc_path}")],
            oracle="reflection",
        )
        case = CorrelatedFinding(canonical=item, consensus_score=0.5)
        positive, _ = reexecute(poc, case, Prober(client, 8), allow_unsafe=True)
        assert positive is False
        assert (client.requests_sent > 0) is sends
        client.close()


def _runtime():
    from tests.agent_support import FakeRuntime

    return FakeRuntime()
