import logging
import re
import socketserver
import threading
from collections.abc import Callable
from io import BufferedIOBase
from typing import Literal
from urllib.parse import unquote_plus, urlsplit

from ..models import Scope, Target
from ..net import NetworkError, NetworkPolicy, ScopedClient
from ..net.ssrf import METADATA_HOSTS, Resolver, system_resolver
from .audit import AuditLog, digest
from .models import ProxyEvent
from .proxy_auth import authorized, client_proxy_url, new_proxy_token

logger = logging.getLogger(__name__)

SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})
MAX_SLEEP_S = 10
DECODE_ROUNDS = 3
MAX_LINE = 8192
MAX_BODY = 64 * 1024
_SLEEP = re.compile(
    r"(?i)(?:\bsleep\s*\(\s*(\d+(?:\.\d+)?)|pg_sleep\s*\(\s*(\d+(?:\.\d+)?)"
    r"|waitfor\s+delay\s+'0:0:(\d+)')"
)
_SQL = re.compile(
    r"(?i)(\bdrop\b|\bdelete\s+from\b|\bupdate\s+\S+\s+set\b|\binsert\s+into\b|"
    r"\btruncate\b|\balter\b|\bshutdown\b|\bxp_cmdshell\b|"
    r";\s*(?:select|insert|update|delete|drop|alter|sleep|waitfor)\b)"
)


def sleep_too_long(text: str) -> bool:
    for match in _SLEEP.finditer(text):
        value = next(group for group in match.groups() if group is not None)
        if float(value) > MAX_SLEEP_S:
            return True
    return False


def destructive(text: str) -> bool:
    """Test the raw text and its percent-decoded forms (up to ``DECODE_ROUNDS``)."""
    for _ in range(DECODE_ROUNDS + 1):
        if _SQL.search(text) or sleep_too_long(text):
            return True
        decoded = unquote_plus(text)
        if decoded == text:
            return False
        text = decoded
    return False


def classify_request(
    method: str,
    url: str,
    body: str,
    *,
    allowed_domains: list[str],
    allow_unsafe: bool,
    finding_url: str = "",
    finding_method: str = "GET",
) -> tuple[Literal["forwards", "rejects"], str]:
    """Return ``(forwards|rejects, reason)`` with no I/O.

    ``POST`` forwards only to replay a finding observed on ``POST`` to that URL.
    Scope, SSRF, rate and the request cap are enforced again by ScopedClient
    when a decision to forward is actually sent.
    """
    verb = method.upper()
    if verb in {"PUT", "PATCH", "DELETE"} or verb not in SAFE_METHODS | {"POST"}:
        return "rejects", "method"
    if verb == "POST" and not (
        allow_unsafe and finding_method.upper() == "POST" and url == finding_url
    ):
        return "rejects", "method"
    if destructive(body) or destructive(url):
        return "rejects", "destructive"
    host = (urlsplit(url).hostname or "").lower()
    if host in METADATA_HOSTS or _literal_metadata(host):
        return "rejects", "ssrf"
    if not Scope(allowed_domains=allowed_domains).is_url_in_scope(url):
        return "rejects", "scope"
    return "forwards", ""


def _literal_metadata(host: str) -> bool:
    import ipaddress

    from ..net.ssrf import is_metadata

    try:
        return is_metadata(ipaddress.ip_address(host))
    except ValueError:
        return False


class _Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


class ScopeProxy:
    """HTTP proxy. Every request is classified, then sent through ScopedClient."""

    def __init__(
        self,
        target: Target,
        policy: NetworkPolicy | None = None,
        *,
        allow_unsafe: bool = False,
        finding_url: str = "",
        finding_method: str = "GET",
        resolver: Resolver = system_resolver,
        audit: AuditLog | None = None,
        token: str | None = None,
    ) -> None:
        self.target = target
        self.allow_unsafe = allow_unsafe
        self.finding_url = finding_url
        self.finding_method = finding_method
        self.audit = audit
        self.token = token if token is not None else new_proxy_token()
        if audit is not None:
            audit.redact_secret(self.token)
        self.events: list[ProxyEvent] = []
        self.client = ScopedClient(target, policy or NetworkPolicy(), resolver=resolver)
        self._server: _Server | None = None
        self._thread: threading.Thread | None = None
        self.url = ""
        self._lock = threading.Lock()

    def start(self, host: str = "127.0.0.1") -> str:
        handler = _bind_handler(self)
        self._server = _Server((host, 0), handler)
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()
        port = int(self._server.server_address[1])
        self.url = self.client_url(f"{host}:{port}")
        return self.url

    def client_url(self, netloc: str) -> str:
        return client_proxy_url(self.token, netloc)

    def close(self) -> None:
        if self._server is not None:
            self._server.shutdown()
            self._server.server_close()
            self._server = None
        self.client.close()

    def decide(self, method: str, url: str, body: str = "") -> ProxyEvent:
        outcome, reason = classify_request(
            method,
            url,
            body,
            allowed_domains=list(self.target.scope.allowed_domains),
            allow_unsafe=self.allow_unsafe,
            finding_url=self.finding_url,
            finding_method=self.finding_method,
        )
        event = ProxyEvent(
            method=method.upper(), url=url, outcome=outcome, reason=reason
        )
        if outcome == "forwards":
            event = self._send(event, body)
        self._record(event)
        return event

    def _send(self, event: ProxyEvent, body: str) -> ProxyEvent:
        try:
            response = self.client.request(
                event.method,
                event.url,
                body=body.encode() if body else None,
            )
        except NetworkError as exc:
            logger.info("Proxy blocked %s %s: %s", event.method, event.url, exc)
            return event.model_copy(
                update={"outcome": "rejects", "reason": _reason(exc), "status": 403}
            )
        if response.redirect_blocked:
            return event.model_copy(
                update={"outcome": "rejects", "reason": "redirect", "status": 403}
            )
        text = response.content[:MAX_BODY].decode("utf-8", "replace")
        return event.model_copy(update={"status": response.status_code, "body": text})

    def _record(self, event: ProxyEvent) -> None:
        with self._lock:
            self.events.append(event)
        if self.audit is not None:
            self.audit.write(
                "proxy",
                method=event.method,
                url=event.url,
                outcome=event.outcome,
                reason=event.reason,
                status=event.status,
                digest=digest(event.body),
            )


def _reason(exc: NetworkError) -> str:
    name = type(exc).__name__
    if name == "SSRFBlocked":
        return "ssrf"
    if name == "RequestBudgetExceeded":
        return "cap"
    if name == "ScopeViolation":
        return "scope"
    return "transport"


def _bind_handler(proxy: ScopeProxy) -> Callable[..., socketserver.BaseRequestHandler]:
    class Handler(socketserver.StreamRequestHandler):
        def handle(self) -> None:
            _serve(self.rfile, self.wfile, proxy)

    return Handler


def _serve(rfile: BufferedIOBase, wfile: BufferedIOBase, proxy: ScopeProxy) -> None:
    try:
        parsed = _read_request(rfile)
    except ValueError as exc:
        _write(wfile, 400, f"rejected: {exc}".encode())
        return
    if parsed is None:
        return
    method, url, headers, body = parsed
    if not authorized(headers.get("proxy-authorization", ""), proxy.token):
        proxy._record(
            ProxyEvent(
                method=method.upper(),
                url=url,
                outcome="rejects",
                reason="auth",
                status=407,
            )
        )
        _write(wfile, 407, b"rejected: auth")
        return
    event = proxy.decide(method, url, body.decode("latin-1", "replace"))
    if event.outcome == "rejects":
        _write(wfile, 403, f"rejected: {event.reason}".encode())
        return
    _write(wfile, event.status or 200, event.body.encode())


def _read_request(
    rfile: BufferedIOBase,
) -> tuple[str, str, dict[str, str], bytes] | None:
    line = rfile.readline(MAX_LINE)
    if not line:
        return None
    parts = line.decode("latin-1").strip().split()
    if len(parts) < 2:
        raise ValueError("bad request line")
    method, target = parts[0], parts[1]
    headers: dict[str, str] = {}
    while True:
        raw = rfile.readline(MAX_LINE)
        if raw in (b"\r\n", b"\n", b""):
            break
        text = raw.decode("latin-1")
        if ":" in text:
            key, value = text.split(":", 1)
            headers[key.strip().lower()] = value.strip()
    length = int(headers.get("content-length", "0") or "0")
    if length > MAX_BODY:
        raise ValueError("body too large")
    body = rfile.read(length) if length else b""
    if target.startswith("/"):
        target = f"http://{headers.get('host', '')}{target}"
    return method, target, headers, body


def fetch_via_proxy(
    proxy_url: str, method: str, url: str, body: str = ""
) -> tuple[int, str]:
    """One request from a sandbox (or the fake runtime) through the proxy."""
    import urllib.error
    import urllib.request

    opener = urllib.request.build_opener(
        urllib.request.ProxyHandler({"http": proxy_url, "https": proxy_url})
    )
    request = urllib.request.Request(
        url, data=body.encode() if body else None, method=method.upper()
    )
    try:
        with opener.open(request, timeout=30) as response:
            payload = response.read(MAX_BODY)
            return int(response.status), payload.decode("utf-8", "replace")
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read(MAX_BODY).decode("utf-8", "replace")


def _write(wfile: BufferedIOBase, status: int, body: bytes) -> None:
    reason = "OK" if status < 400 else "Blocked"
    head = (
        f"HTTP/1.1 {status} {reason}\r\n"
        f"Content-Length: {len(body)}\r\n"
        "Content-Type: text/plain\r\n"
        "Connection: close\r\n\r\n"
    )
    wfile.write(head.encode() + body)
