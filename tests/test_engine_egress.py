import socket
from pathlib import Path
from urllib.parse import urlsplit

import pytest

from haris.core.engine import ScanEngine
from haris.models import Target
from haris.scanners.base import ToolRun
from haris.scanners.nikto_scanner import NiktoScanner

PUBLIC = "93.184.216.34"
HOST = "t.example"
PORT = 8080
PUBLIC_LOOKUPS = 2
connect_to_proxy = socket.create_connection


class ProxyUsingNikto(NiktoScanner):
    """Real adapter whose process is replaced by a CONNECT through its proxy."""

    def __init__(self) -> None:
        super().__init__()
        self.proxy_url = ""
        self.reply = b""

    def _check_tool_available(self, binary: str) -> bool:
        return True

    def _run_to_file(self, cmd: list[str], output_file: Path, timeout: int) -> ToolRun:
        self.proxy_url = cmd[cmd.index("-useproxy") + 1]
        netloc = urlsplit(self.proxy_url).netloc
        host, port = netloc.rsplit(":", 1)
        with connect_to_proxy((host, int(port)), timeout=5) as conn:
            conn.sendall(f"CONNECT {HOST}:{PORT} HTTP/1.1\r\n\r\n".encode())
            self.reply = conn.recv(256)
        return ToolRun(0, "", "", False)


class Rebinder:
    """Public for the pre-flight and the pre-start re-check, loopback afterwards."""

    def __init__(self) -> None:
        self.calls = 0

    def __call__(self, _host: str, _port: int) -> list[str]:
        self.calls += 1
        return [PUBLIC] if self.calls <= PUBLIC_LOOKUPS else ["127.0.0.1"]


@pytest.fixture
def dialed(monkeypatch: pytest.MonkeyPatch) -> list[tuple[str, int]]:
    seen: list[tuple[str, int]] = []

    def refuse(address: tuple[str, int], timeout: float | None = None) -> socket.socket:
        seen.append(address)
        raise OSError("no network in tests")

    monkeypatch.setattr("haris.net.egress_proxy.socket.create_connection", refuse)
    return seen


def test_tool_reaches_only_the_preflight_address_after_dns_changes(
    dialed: list[tuple[str, int]],
) -> None:
    nikto = ProxyUsingNikto()
    engine = ScanEngine(scanners=[nikto], parallel=1, resolver=Rebinder())
    engine.run(Target(base_url=f"http://{HOST}:{PORT}"))

    assert nikto.reply.startswith(b"HTTP/1.1 502")
    assert dialed == [(PUBLIC, PORT)]


def test_proxy_stops_when_the_scan_ends(dialed: list[tuple[str, int]]) -> None:
    nikto = ProxyUsingNikto()
    ScanEngine(scanners=[nikto], parallel=1, resolver=Rebinder()).run(
        Target(base_url=f"http://{HOST}:{PORT}")
    )

    host, port = urlsplit(nikto.proxy_url).netloc.rsplit(":", 1)
    with pytest.raises(OSError), connect_to_proxy((host, int(port)), timeout=2):
        pass
