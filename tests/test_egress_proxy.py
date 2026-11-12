import socket
import threading
from collections.abc import Iterator

import pytest

from haris.net.egress_proxy import EgressProxy
from haris.net.ssrf import Resolver

SOCKET_TIMEOUT_S = 5.0
RESPONSE = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok"
PUBLIC_IP = "93.184.216.34"


class FakeNet:
    """Records dialed addresses and serves the far end of each connection."""

    def __init__(self, *, echo: bool = False) -> None:
        self.dialed: list[tuple[str, int]] = []
        self.resolved: list[tuple[str, int]] = []
        self.received: list[bytes] = []
        self._echo = echo

    def resolver_for(self, address: str) -> Resolver:
        def resolve(host: str, port: int) -> list[str]:
            self.resolved.append((host, port))
            return [address]

        return resolve

    def connect(self, ip: str, port: int) -> socket.socket:
        self.dialed.append((ip, port))
        near, far = socket.socketpair()
        far.settimeout(SOCKET_TIMEOUT_S)
        threading.Thread(
            target=self._echo_loop if self._echo else self._serve_http,
            args=(far,),
            daemon=True,
        ).start()
        return near

    def _echo_loop(self, far: socket.socket) -> None:
        with far:
            while data := far.recv(4096):
                far.sendall(data)

    def _serve_http(self, far: socket.socket) -> None:
        with far:
            buffer = b""
            while b"\r\n\r\n" not in buffer:
                buffer += far.recv(4096)
            head, _, body = buffer.partition(b"\r\n\r\n")
            length = 0
            for line in head.split(b"\r\n")[1:]:
                name, _, value = line.partition(b":")
                if name.lower() == b"content-length":
                    length = int(value)
            while len(body) < length:
                body += far.recv(4096)
            self.received.append(head + b"\r\n\r\n" + body)
            far.sendall(RESPONSE)


@pytest.fixture
def started() -> Iterator[list[EgressProxy]]:
    proxies: list[EgressProxy] = []
    yield proxies
    for proxy in proxies:
        proxy.close()


def make_proxy(
    started: list[EgressProxy],
    net: FakeNet,
    *,
    allow_private: bool = False,
    pinned: dict[tuple[str, int], str] | None = None,
    resolves_to: str = "127.0.0.1",
) -> int:
    proxy = EgressProxy(
        allow_private=allow_private,
        pinned=pinned or {},
        resolver=net.resolver_for(resolves_to),
        connector=net.connect,
    )
    started.append(proxy)
    return int(proxy.start().rsplit(":", 1)[1])


def open_client(port: int) -> socket.socket:
    return socket.create_connection(("127.0.0.1", port), timeout=SOCKET_TIMEOUT_S)


def read_until_close(client: socket.socket) -> bytes:
    chunks = []
    while chunk := client.recv(4096):
        chunks.append(chunk)
    return b"".join(chunks)


def exchange(port: int, *payload: bytes) -> bytes:
    with open_client(port) as client:
        for part in payload:
            client.sendall(part)
        return read_until_close(client)


def get(host: str, port: int = 80) -> bytes:
    return f"GET http://{host}:{port}/ HTTP/1.1\r\nHost: {host}\r\n\r\n".encode()


def test_pinned_host_is_dialed_without_resolving(started: list[EgressProxy]) -> None:
    net = FakeNet()
    port = make_proxy(started, net, pinned={("t.example", 80): PUBLIC_IP})
    reply = exchange(port, get("T.Example"))
    assert reply.endswith(b"ok")
    assert net.dialed == [(PUBLIC_IP, 80)]
    assert net.resolved == []


@pytest.mark.parametrize(
    ("allow_private", "status", "dialed"),
    [(False, b"403", []), (True, b"200", [("127.0.0.1", 80)])],
)
def test_unpinned_loopback_follows_allow_private(
    started: list[EgressProxy],
    allow_private: bool,
    status: bytes,
    dialed: list[tuple[str, int]],
) -> None:
    net = FakeNet()
    port = make_proxy(started, net, allow_private=allow_private)
    reply = exchange(port, get("rebind.example"))
    assert reply.split(b" ", 2)[1] == status
    assert net.dialed == dialed


@pytest.mark.parametrize(
    ("host", "pinned", "resolves_to"),
    [
        ("169.254.169.254", {}, "169.254.169.254"),
        ("rebind.example", {}, "169.254.169.254"),
        ("metadata.google.internal", {}, PUBLIC_IP),
        ("t.example", {("t.example", 80): "169.254.169.254"}, PUBLIC_IP),
        (
            "metadata.google.internal",
            {("metadata.google.internal", 80): PUBLIC_IP},
            PUBLIC_IP,
        ),
    ],
)
def test_metadata_blocked_even_when_private_allowed(
    started: list[EgressProxy],
    host: str,
    pinned: dict[tuple[str, int], str],
    resolves_to: str,
) -> None:
    net = FakeNet()
    port = make_proxy(
        started, net, allow_private=True, pinned=pinned, resolves_to=resolves_to
    )
    assert exchange(port, get(host)).startswith(b"HTTP/1.1 403")
    assert net.dialed == []


def test_connect_tunnel_relays_both_ways(started: list[EgressProxy]) -> None:
    net = FakeNet(echo=True)
    port = make_proxy(started, net, pinned={("t.example", 443): PUBLIC_IP})
    with open_client(port) as client:
        client.sendall(b"CONNECT t.example:443 HTTP/1.1\r\nHost: t.example:443\r\n\r\n")
        assert client.recv(4096).startswith(b"HTTP/1.1 200 Connection Established")
        client.sendall(b"ping")
        assert client.recv(4096) == b"ping"
        client.sendall(b"pong")
        assert client.recv(4096) == b"pong"
    assert net.dialed == [(PUBLIC_IP, 443)]


def test_connect_accepts_bracketed_ipv6_literal(started: list[EgressProxy]) -> None:
    net = FakeNet(echo=True)
    port = make_proxy(started, net)
    with open_client(port) as client:
        client.sendall(b"CONNECT [2606:4700::1111]:443 HTTP/1.1\r\n\r\n")
        assert client.recv(4096).startswith(b"HTTP/1.1 200")
    assert net.dialed == [("2606:4700::1111", 443)]
    assert net.resolved == []


def test_plain_post_is_rewritten_to_origin_form(started: list[EgressProxy]) -> None:
    net = FakeNet()
    port = make_proxy(started, net, pinned={("t.example", 80): PUBLIC_IP})
    body = b"a=1&b=" + b"x" * 5000
    head = (
        b"POST http://t.example/submit?x=1 HTTP/1.1\r\nHost: t.example\r\n"
        b"Proxy-Authorization: Basic Zm9vOmJhcg==\r\nProxy-Connection: keep-alive\r\n"
        b"Connection: keep-alive\r\nContent-Length: "
        + str(len(body)).encode()
        + b"\r\n\r\n"
    )
    assert exchange(port, head, body).endswith(b"ok")
    sent_head, _, sent_body = net.received[0].partition(b"\r\n\r\n")
    lines = sent_head.decode().split("\r\n")
    names = [line.split(":", 1)[0].lower() for line in lines[1:]]
    assert lines[0] == "POST /submit?x=1 HTTP/1.1"
    assert not [name for name in names if name.startswith("proxy-")]
    assert [line for line in lines if line.lower().startswith("connection:")] == [
        "Connection: close"
    ]
    assert sent_body == body


@pytest.mark.parametrize(
    "request_line",
    [
        "GET /path HTTP/1.1",
        "GET https://t.example/ HTTP/1.1",
        "CONNECT t.example HTTP/1.1",
        "GARBAGE",
    ],
)
def test_unsupported_request_forms_get_400(
    started: list[EgressProxy], request_line: str
) -> None:
    net = FakeNet()
    port = make_proxy(started, net, pinned={("t.example", 80): PUBLIC_IP})
    assert exchange(
        port, f"{request_line}\r\nHost: t.example\r\n\r\n".encode()
    ).startswith(b"HTTP/1.1 400")
    assert net.dialed == []


def test_pin_does_not_cover_other_ports(started: list[EgressProxy]) -> None:
    net = FakeNet()
    port = make_proxy(
        started, net, pinned={("t.example", 80): PUBLIC_IP}, resolves_to="8.8.8.8"
    )
    assert exchange(port, get("t.example", 8080)).endswith(b"ok")
    assert net.resolved == [("t.example", 8080)]
    assert net.dialed == [("8.8.8.8", 8080)]


def test_close_is_idempotent_and_stops_listening() -> None:
    proxy = EgressProxy(allow_private=False, pinned={})
    port = int(proxy.start().rsplit(":", 1)[1])
    proxy.close()
    proxy.close()
    with pytest.raises(OSError):
        socket.create_connection(("127.0.0.1", port), timeout=SOCKET_TIMEOUT_S)
