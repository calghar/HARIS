import http.server
import threading
import urllib.error
import urllib.request
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from urllib.parse import urlsplit

import pytest

from haris.agent.audit import AuditLog
from haris.agent.proxy import ScopeProxy, classify_request
from haris.models import Scope, Target
from haris.net import NetworkPolicy
from haris.net.ssrf import Resolver

MATRIX = [
    (False, "GET", "https://example.com/search?q=1", "", "forwards"),
    (False, "GET", "https://evil.test/", "", "rejects"),
    (False, "GET", "http://169.254.169.254/latest/meta-data", "", "rejects"),
    (False, "POST", "https://example.com/login", "", "rejects"),
    (True, "POST", "https://example.com/login", "", "forwards"),
    (True, "DELETE", "https://example.com/item/1", "", "rejects"),
    (True, "POST", "https://example.com/q", "id=1;DROP TABLE users", "rejects"),
]


@pytest.mark.parametrize("unsafe,method,url,body,outcome", MATRIX)
def test_proxy_egress_matrix(
    unsafe: bool, method: str, url: str, body: str, outcome: str
):
    """Scenario: Proxy egress matrix."""
    decision, _reason = classify_request(
        method,
        url,
        body,
        allowed_domains=["example.com"],
        allow_unsafe=unsafe,
    )
    assert decision == outcome


class _Quiet(http.server.BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        if self.path.startswith("/go"):
            self.send_response(302)
            self.send_header("Location", "http://evil.test/nope")
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        body = b"pong"
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

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


def _resolver(host: str) -> Resolver:
    def resolve(name: str, _port: int) -> list[str]:
        if name == host:
            return ["127.0.0.1"]
        raise OSError(name)

    return resolve


def _proxy(
    domains: list[str],
    *,
    allow_private: bool,
    max_requests: int = 20,
    resolver: Resolver | None = None,
) -> ScopeProxy:
    target = Target(
        base_url=f"http://{domains[0]}",
        scope=Scope(
            allowed_domains=domains,
            rate_limit_rps=1000,
            max_requests=max_requests,
            allowed_methods=["GET", "HEAD", "OPTIONS", "POST"],
        ),
    )
    proxy = ScopeProxy(
        target,
        NetworkPolicy(allow_private=allow_private),
        resolver=resolver or _resolver(domains[0]),
    )
    proxy.start()
    return proxy


def _get(proxy: ScopeProxy, url: str) -> tuple[int, str]:
    opener = urllib.request.build_opener(
        urllib.request.ProxyHandler({"http": proxy.url})
    )
    request = urllib.request.Request(url, method="GET")
    try:
        with opener.open(request, timeout=5) as response:
            return int(response.status), response.read().decode()
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode()


def test_proxy_forwards_in_scope_and_blocks_the_rest():
    """In-scope is logged; out-of-scope, metadata, redirect and cap are blocked."""
    with _serve() as base:
        port = base.rsplit(":", 1)[1]
        proxy = _proxy(["fixture.test"], allow_private=True, max_requests=2)
        try:
            status, body = _get(proxy, f"http://fixture.test:{port}/ping")
            assert status == 200 and body == "pong"
            blocked, text = _get(proxy, "http://evil.test/")
            assert blocked == 403 and "scope" in text
            # urllib bypasses a proxy for 169.254.169.254, so this hop stays in-process.
            meta = proxy.decide("GET", "http://169.254.169.254/latest/meta-data")
            assert meta.outcome == "rejects" and meta.reason == "ssrf"
            hop, hop_text = _get(proxy, f"http://fixture.test:{port}/go")
            assert hop == 403 and "redirect" in hop_text
            capped, capped_text = _get(proxy, f"http://fixture.test:{port}/ping")
            assert capped == 403 and "cap" in capped_text
        finally:
            proxy.close()
    reasons = {event.reason for event in proxy.events if event.outcome == "rejects"}
    assert {"scope", "ssrf", "redirect", "cap"} <= reasons
    assert any(
        event.outcome == "forwards" and event.status == 200 for event in proxy.events
    )


def test_proxy_blocks_a_private_address_that_is_named_in_scope():
    proxy = _proxy(["10.1.1.1"], allow_private=False, max_requests=5)
    try:
        status, text = _get(proxy, "http://10.1.1.1/")
        assert status == 403 and "ssrf" in text
    finally:
        proxy.close()
    assert any(event.reason == "ssrf" for event in proxy.events)


class _Hits(http.server.BaseHTTPRequestHandler):
    hits = 0

    def do_GET(self) -> None:
        type(self).hits += 1
        body = b"pong"
        self.send_response(200)
        self.send_header("Content-Length", "4")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_args: object) -> None:
        return None


def _status(proxy_url: str, url: str) -> tuple[int, str]:
    opener = urllib.request.build_opener(
        urllib.request.ProxyHandler({"http": proxy_url, "https": proxy_url})
    )
    try:
        with opener.open(urllib.request.Request(url), timeout=5) as response:
            return int(response.status), response.read().decode()
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode()


def test_proxy_rejects_a_missing_or_wrong_token(tmp_path: Path):
    """Unauthenticated and wrong-token requests are 407 and do not go upstream."""
    _Hits.hits = 0
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _Hits)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    audit = AuditLog(tmp_path / "audit.jsonl")
    proxy = ScopeProxy(
        Target(
            base_url="http://fixture.test",
            scope=Scope(
                allowed_domains=["fixture.test"],
                rate_limit_rps=1000,
                max_requests=20,
            ),
        ),
        NetworkPolicy(allow_private=True),
        resolver=_resolver("fixture.test"),
        audit=audit,
    )
    proxy.start()
    parts = urlsplit(proxy.url)
    bare = f"http://{parts.hostname}:{parts.port}"
    wrong = f"http://job:not-the-token@{parts.hostname}:{parts.port}"
    target = f"http://fixture.test:{server.server_address[1]}/ping"
    try:
        missing, missing_body = _status(bare, target)
        forged, forged_body = _status(wrong, target)
        assert _Hits.hits == 0
        assert missing == 407 and "auth" in missing_body
        assert forged == 407 and "auth" in forged_body
        ok, body = _status(proxy.url, target)
        assert ok == 200 and body == "pong"
        assert _Hits.hits == 1
        audit.write("note", proxy=proxy.url)
    finally:
        proxy.close()
        audit.close()
        server.shutdown()
        server.server_close()
    text = (tmp_path / "audit.jsonl").read_text()
    assert proxy.token not in text
    assert "[REDACTED]" in text
    assert text.count('"reason": "auth"') == 2
