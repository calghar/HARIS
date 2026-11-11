import http.server
import threading
from collections.abc import Iterator
from contextlib import contextmanager

import pytest

from haris.agent.policy import bind_policy, policy_for_web
from haris.agent.settings import load_agent_settings
from haris.core.engine import ScanEngine
from haris.llm.base import BaseLLMBackend
from haris.models import LLMResponse, Scope, Target
from haris.net import NetworkPolicy
from haris.verify import VerifyMode

ORDER = [
    "correlate",
    "suppress",
    "replay",
    "llm_verdict",
    "agent",
    "confidence",
    "risk",
    "report",
]


class _Silent(BaseLLMBackend):
    name = "silent"
    model = "fake-agent"

    def complete(
        self,
        prompt: str,
        *,
        system: str = "",
        temperature: float = 0.2,
        max_tokens: int = 2048,
    ) -> LLMResponse:
        raise AssertionError("no finding, no model call")


class _Quiet(http.server.BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        self.send_response(200)
        self.end_headers()

    def log_message(self, *_args: object) -> None:
        return None


@contextmanager
def _serve() -> Iterator[str]:
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _Quiet)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}"
    finally:
        server.shutdown()
        server.server_close()


def test_stage_order_includes_the_agent(monkeypatch: pytest.MonkeyPatch):
    """Scenario: Stage order recorded."""
    monkeypatch.delenv("HARIS_AGENT_DISABLED", raising=False)
    policy = policy_for_web(is_admin=True, target_authorised=True, output_dir="output")
    assert policy is not None
    token = bind_policy(policy)
    try:
        with _serve() as url:
            target = Target(base_url=url, scope=Scope(rate_limit_rps=1000))
            engine = ScanEngine(
                scanners=[],
                verify=VerifyMode.LLM,
                llm_backend=_Silent(),
                network_policy=NetworkPolicy(allow_private=True),
            )
            session = engine.run(target)
        assert session.stage_log == ORDER
    finally:
        from haris.agent.policy import reset_policy

        reset_policy(token)


def test_disabled_env_skips_the_agent_stage(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("HARIS_AGENT_DISABLED", "1")
    assert policy_for_web(is_admin=True, target_authorised=True, output_dir="o") is None
    assert "xss_reflected" in load_agent_settings().classes
