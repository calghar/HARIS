import json
import re
from collections.abc import Callable, Iterator, Mapping
from contextlib import contextmanager
from typing import Any
from urllib.parse import urlsplit

import requests

from haris.ai_security.scanner import AiSecurityScanner
from haris.models import (
    AuthConfig,
    Finding,
    ScanContext,
    ScannerResult,
    Scope,
    Target,
)
from haris.net import NetworkPolicy, ScopedClient

from .checks_support import NOT_FOUND, Route
from .fake_transport import FakeNet, Reply

ALL_METHODS = ["GET", "HEAD", "OPTIONS", "POST"]
JSON_TYPE = {"Content-Type": "application/json"}


def scope_with_post() -> Scope:
    return Scope(rate_limit_rps=1000.0, allowed_methods=ALL_METHODS)


def json_reply(payload: Any, status: int = 200, **headers: str) -> Reply:
    return status, {**JSON_TYPE, **headers}, json.dumps(payload).encode()


def rpc_reply(result: Any, **headers: str) -> Reply:
    return json_reply({"jsonrpc": "2.0", "id": 1, "result": result}, 200, **headers)


def initialize_result(**capabilities: Any) -> dict[str, Any]:
    return {
        "protocolVersion": "2025-06-18",
        "capabilities": capabilities or {"tools": {}},
        "serverInfo": {"name": "test-mcp", "version": "1"},
    }


@contextmanager
def local_client(base_url: str, *, post: bool = True) -> Iterator[ScopedClient]:
    scope = scope_with_post() if post else Scope(rate_limit_rps=1000.0)
    target = Target(base_url=base_url, scope=scope)
    with ScopedClient(target, NetworkPolicy(allow_private=True)) as client:
        yield client


def run_ai(
    client: ScopedClient, **options: Any
) -> tuple[ScannerResult, AiSecurityScanner]:
    scanner = AiSecurityScanner(options)
    result = scanner.scan(client.target, ScanContext(http=client))
    return result, scanner


def classes(findings: list[Finding]) -> set[str]:
    return {f.vuln_class for f in findings}


def net_with(
    routes: Mapping[str, Route] | None = None,
    *,
    base_url: str = "https://example.com",
    auth: AuthConfig | None = None,
    allow_private: bool = False,
    post: bool = True,
) -> FakeNet:
    """A fake host with POST in scope (and optional auth); routes match by path."""
    table = routes or {}

    def handler(request: requests.PreparedRequest) -> Reply:
        route = table.get(urlsplit(request.url or "").path, NOT_FOUND)
        return route(request) if callable(route) else route

    return FakeNet(
        handler,
        base_url=base_url,
        scope=scope_with_post() if post else Scope(rate_limit_rps=1000.0),
        auth=auth,
        allow_private=allow_private,
        resolves={"localhost": ["127.0.0.1"]},
    )


CHAT = "/v1/chat/completions"
MODELS = json_reply({"object": "list", "data": [{"id": "m1"}]})
CANARY = re.compile(r"HARIS-CANARY-[0-9a-f]{16}")
BOTH: dict[str, Any] = {"active": True, "authorised": True}


def completion(text: str, **extra: Any) -> dict[str, Any]:
    return {"choices": [{"message": {"role": "assistant", "content": text}}], **extra}


class FakeChat:
    """A scripted chat route; ``model`` maps the user prompt to the reply text."""

    def __init__(
        self,
        model: Callable[[str], str],
        *,
        status: int = 200,
        headers: dict[str, str] | None = None,
        extra: dict[str, Any] | None = None,
    ) -> None:
        self.model, self.status = model, status
        self.headers, self.extra = headers or {}, extra or {}
        self.bodies: list[dict[str, Any]] = []

    def __call__(self, request: requests.PreparedRequest) -> Reply:
        if request.method != "POST":
            return json_reply({}, status=405)
        try:
            body = json.loads(request.body or "")
            prompt = body["messages"][0]["content"]
        except (ValueError, KeyError, TypeError):
            return json_reply({"error": "bad request"}, status=400)
        self.bodies.append(body)
        if self.status != 200:
            return json_reply({"error": "no"}, status=self.status, **self.headers)
        return json_reply(
            completion(self.model(prompt), **self.extra), 200, **self.headers
        )

    @property
    def prompts(self) -> list[str]:
        return [b["messages"][0]["content"] for b in self.bodies]


def obedient(prompt: str) -> str:
    """Repeats the canary only after an instruction override."""
    if "ignore" not in prompt.lower():
        return "Four."
    return f"Sure: {' '.join(CANARY.findall(prompt))}"
