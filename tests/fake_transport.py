from collections.abc import Callable
from typing import Any

import requests
from requests.adapters import HTTPAdapter
from requests.structures import CaseInsensitiveDict

from haris.models import AuthConfig, Scope, Target
from haris.net import NetworkPolicy, ScopedClient

type Reply = tuple[int, dict[str, str], bytes]
type Handler = Callable[[requests.PreparedRequest], Reply]


class FakeClock:
    """Deterministic clock whose sleep advances time."""

    def __init__(self) -> None:
        self.now = 1000.0
        self.sleeps: list[float] = []

    def __call__(self) -> float:
        return self.now

    def sleep(self, seconds: float) -> None:
        self.sleeps.append(seconds)
        self.now += seconds


class FakeAdapter(HTTPAdapter):
    """Transport boundary: records prepared requests and answers from a handler."""

    def __init__(self, handler: Handler) -> None:
        super().__init__()
        self.handler = handler
        self.sent: list[requests.PreparedRequest] = []

    def send(  # type: ignore[override]  # fake ignores the transport options
        self, request: requests.PreparedRequest, **_options: Any
    ) -> requests.Response:
        self.sent.append(request)
        status, headers, body = self.handler(request)
        response = requests.Response()
        response.status_code = status
        response.headers = CaseInsensitiveDict(headers)
        response._content = body
        response._content_consumed = True  # type: ignore[attr-defined]  # marks body read
        response.url = request.url or ""
        response.request = request
        return response


def ok(body: bytes = b"ok", **headers: str) -> Reply:
    return 200, dict(headers), body


class FakeNet:
    """ScopedClient wired to a fake transport and a fake resolver."""

    def __init__(
        self,
        handler: Handler | None = None,
        *,
        base_url: str = "https://example.com",
        scope: Scope | None = None,
        auth: AuthConfig | None = None,
        resolves: dict[str, list[str]] | None = None,
        allow_private: bool = False,
    ) -> None:
        self.clock = FakeClock()
        self.adapter = FakeAdapter(handler or (lambda _req: ok()))
        self.resolves = resolves if resolves is not None else {}
        self.resolver_calls: list[str] = []
        target = Target(
            base_url=base_url,
            scope=scope or Scope(rate_limit_rps=1000.0),
            auth=auth or AuthConfig(),
        )
        self.client = ScopedClient(
            target,
            NetworkPolicy(allow_private=allow_private),
            resolver=self._resolve,
            adapter_factory=lambda _host: self.adapter,
            clock=self.clock,
            sleep=self.clock.sleep,
        )

    def _resolve(self, host: str, _port: int) -> list[str]:
        self.resolver_calls.append(host)
        return self.resolves.get(host, ["93.184.216.34"])

    @property
    def sent(self) -> list[requests.PreparedRequest]:
        return self.adapter.sent
