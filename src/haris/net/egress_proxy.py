import logging
import selectors
import socket
import socketserver
import threading
from collections.abc import Callable
from urllib.parse import SplitResult, urlsplit

from .errors import SSRFBlocked
from .ssrf import Resolver, system_resolver, vet_addresses, vet_host

logger = logging.getLogger(__name__)

MAX_HEAD_BYTES = 64 * 1024
HEAD_TIMEOUT_S = 10.0
CONNECT_TIMEOUT_S = 10.0
IDLE_TIMEOUT_S = 60.0
POLL_INTERVAL_S = 0.02
RECV_BYTES = 64 * 1024
HEAD_END = b"\r\n\r\n"
CONNECT_REPLY = b"HTTP/1.1 200 Connection Established\r\n\r\n"
DEFAULT_HTTP_PORT = 80

type Connector = Callable[[str, int], socket.socket]


def dial(ip: str, port: int) -> socket.socket:
    return socket.create_connection((ip, port), timeout=CONNECT_TIMEOUT_S)


def _reply(client: socket.socket, status: str, reason: str) -> None:
    body = reason.encode("utf-8", errors="replace")
    head = (
        f"HTTP/1.1 {status}\r\nContent-Type: text/plain\r\n"
        f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n"
    )
    client.sendall(head.encode("ascii") + body)


def _read_head(client: socket.socket) -> tuple[bytes, bytes] | None:
    """Request head without its terminator, plus any bytes read past it."""
    buffer = b""
    while HEAD_END not in buffer:
        if len(buffer) > MAX_HEAD_BYTES:
            return None
        chunk = client.recv(RECV_BYTES)
        if not chunk:
            return None
        buffer += chunk
    head, _, rest = buffer.partition(HEAD_END)
    return head, rest


def _origin_form(parts: SplitResult) -> str:
    return (parts.path or "/") + (f"?{parts.query}" if parts.query else "")


def _pump(client: socket.socket, upstream: socket.socket) -> None:
    """Copy both ways; a client half-close is passed on, an upstream close ends it."""
    client.settimeout(IDLE_TIMEOUT_S)
    upstream.settimeout(IDLE_TIMEOUT_S)
    with selectors.DefaultSelector() as selector:
        selector.register(client, selectors.EVENT_READ, (client, upstream))
        selector.register(upstream, selectors.EVENT_READ, (upstream, client))
        while selector.get_map():
            events = selector.select(IDLE_TIMEOUT_S)
            if not events:
                return
            for key, _ in events:
                source, sink = key.data
                data = source.recv(RECV_BYTES)
                if data:
                    sink.sendall(data)
                    continue
                selector.unregister(source)
                sink.shutdown(socket.SHUT_WR)
                if source is upstream:
                    return


class EgressProxy:
    """Forward proxy that dials only vetted IPs, so DNS changes cannot redirect it."""

    def __init__(
        self,
        *,
        allow_private: bool,
        pinned: dict[tuple[str, int], str],
        resolver: Resolver = system_resolver,
        connector: Connector = dial,
    ) -> None:
        self._allow_private = allow_private
        self._pinned = {(host.lower(), port): ip for (host, port), ip in pinned.items()}
        self._resolver = resolver
        self._connector = connector
        self._server: socketserver.ThreadingTCPServer | None = None
        self._thread: threading.Thread | None = None

    def start(self, host: str = "127.0.0.1") -> str:
        proxy = self

        class Handler(socketserver.BaseRequestHandler):
            def handle(self) -> None:
                proxy._serve(self.request)

        class Server(socketserver.ThreadingTCPServer):
            daemon_threads = True
            allow_reuse_address = True

        self._server = Server((host, 0), Handler)
        self._thread = threading.Thread(
            target=self._server.serve_forever, args=(POLL_INTERVAL_S,), daemon=True
        )
        self._thread.start()
        return f"http://{host}:{self._server.server_address[1]}"

    def close(self) -> None:
        server, thread = self._server, self._thread
        self._server = self._thread = None
        if server is None or thread is None:
            return
        server.shutdown()
        server.server_close()
        thread.join()

    def _destination(self, host: str, port: int) -> str:
        pinned = self._pinned.get((host, port))
        if pinned is not None:
            return vet_addresses(host, [pinned], allow_private=True)
        return vet_host(
            host, port, allow_private=self._allow_private, resolver=self._resolver
        )

    def _serve(self, client: socket.socket) -> None:
        client.settimeout(HEAD_TIMEOUT_S)
        try:
            self._route(client)
        except OSError as exc:
            logger.debug("Egress connection ended: %s", exc)

    def _route(self, client: socket.socket) -> None:
        read = _read_head(client)
        lines = read[0].decode("latin-1").split("\r\n") if read else [""]
        words = lines[0].split(" ")
        if read is None or len(words) != 3:
            _reply(client, "400 Bad Request", "malformed request head")
            return
        method, uri, version = words
        tunnel = method.upper() == "CONNECT"
        parts = urlsplit(f"//{uri}" if tunnel else uri)
        try:
            host, port = (
                parts.hostname,
                parts.port or (None if tunnel else DEFAULT_HTTP_PORT),
            )
        except ValueError:
            host, port = None, None
        if (
            host is None
            or port is None
            or (not tunnel and (parts.scheme != "http" or not parts.netloc))
        ):
            _reply(
                client,
                "400 Bad Request",
                "need CONNECT host:port or an absolute http:// URI",
            )
            return
        try:
            ip = self._destination(host, port)
        except SSRFBlocked as exc:
            logger.info("Egress blocked %s:%d: %s", host, port, exc)
            _reply(client, "403 Forbidden", str(exc))
            return
        try:
            upstream = self._connector(ip, port)
        except OSError as exc:
            logger.info("Egress connect failed %s:%d: %s", host, port, exc)
            _reply(client, "502 Bad Gateway", f"cannot reach {host}:{port}")
            return
        with upstream:
            if tunnel:
                client.sendall(CONNECT_REPLY)
                first = read[1]
            else:
                kept = [
                    h
                    for h in lines[1:]
                    if not h.lower().startswith(("proxy-", "connection:"))
                ]
                request = [
                    f"{method} {_origin_form(parts)} {version}",
                    *kept,
                    "Connection: close",
                ]
                first = ("\r\n".join(request) + "\r\n\r\n").encode("latin-1") + read[1]
            if first:
                upstream.sendall(first)
            _pump(client, upstream)
