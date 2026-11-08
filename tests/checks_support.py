import http.server
import threading
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from typing import Any
from urllib.parse import urlsplit

import requests

from haris.core.scanner import BaseScanner
from haris.models import Finding, ScanContext, ScannerResult, Scope, Target
from haris.net import NetworkPolicy, ScopedClient

from .fake_transport import FakeNet, Reply

type Route = Reply | Callable[[requests.PreparedRequest], Reply]

HTML_SHELL = (
    b"<!doctype html><html><head><title>Acme App</title></head>"
    b"<body><div id=root></div><script src=/static/main.js></script></body></html>"
)
NOT_FOUND: Reply = (404, {"Content-Type": "text/html"}, b"<h1>Not Found</h1>")
SENSITIVE_PATHS_COUNT = 14


def html(body: bytes = HTML_SHELL, status: int = 200, **headers: str) -> Reply:
    return status, {"Content-Type": "text/html; charset=utf-8", **headers}, body


def site(
    routes: dict[str, Route] | None = None,
    *,
    fallback: Route = NOT_FOUND,
    base_url: str = "https://example.com",
    scope: Scope | None = None,
) -> FakeNet:
    """A fake host answering by exact path (query ignored); else the fallback."""
    table = routes or {}

    def handler(request: requests.PreparedRequest) -> Reply:
        route = table.get(urlsplit(request.url or "").path, fallback)
        return route(request) if callable(route) else route

    return FakeNet(handler, base_url=base_url, scope=scope)


def run_check(
    scanner: BaseScanner, net: FakeNet | ScopedClient, **context: Any
) -> ScannerResult:
    client = net.client if isinstance(net, FakeNet) else net
    return scanner.scan(client.target, ScanContext(http=client, **context))


def titles(findings: list[Finding]) -> list[str]:
    return [f.title for f in findings]


class _Handler(http.server.BaseHTTPRequestHandler):
    reply: Callable[[str], Reply]

    def do_GET(self) -> None:
        status, headers, body = self.reply(self.path)
        self.send_response(status)
        for name, value in headers.items():
            self.send_header(name, value)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format: str, *args: object) -> None:  # noqa: A002
        return None


@contextmanager
def local_site(reply: Callable[[str], Reply]) -> Iterator[ScopedClient]:
    """A real HTTP server on an ephemeral 127.0.0.1 port, wrapped in a ScopedClient."""
    handler = type("Handler", (_Handler,), {"reply": staticmethod(reply)})
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    url = f"http://127.0.0.1:{server.server_address[1]}"
    target = Target(base_url=url, scope=Scope(rate_limit_rps=1000.0))
    try:
        with ScopedClient(target, NetworkPolicy(allow_private=True)) as client:
            yield client
    finally:
        server.shutdown()
        server.server_close()
