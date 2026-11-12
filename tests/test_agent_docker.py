import http.server
import subprocess
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from urllib.parse import urlsplit

import pytest

from haris.agent.docker_runtime import DockerRuntime
from haris.agent.proxy import ScopeProxy
from haris.agent.runtime import RuntimeSpec
from haris.models import Scope, Target
from haris.net import NetworkPolicy
from haris.net.ssrf import Resolver

pytestmark = pytest.mark.docker

ROOT = Path(__file__).resolve().parents[1]
IMAGE = "haris-agent-sandbox:local"
DIRECT = (
    "import socket\n"
    "s = socket.socket()\n"
    "s.settimeout(3)\n"
    "try:\n"
    "    s.connect(('10.255.255.1', 9))\n"
    "    print('connected')\n"
    "except OSError as exc:\n"
    "    print(type(exc).__name__)\n"
)
CAPS = "print(next(x.split()[1] for x in open('/proc/self/status') if 'CapEff' in x))"


class _Pong(http.server.BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        body = b"pong"
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", "4")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_args: object) -> None:
        return None


@contextmanager
def _serve() -> Iterator[int]:
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _Pong)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        yield int(server.server_address[1])
    finally:
        server.shutdown()
        server.server_close()


def _resolver() -> Resolver:
    def resolve(host: str, _port: int) -> list[str]:
        if host == "fixture.test":
            return ["127.0.0.1"]
        raise OSError(host)

    return resolve


def _build() -> str:
    subprocess.run(
        ["docker", "build", "--load", "--pull=false", "-t", IMAGE, "docker/agent"],
        cwd=ROOT,
        check=True,
    )
    image = subprocess.check_output(
        ["docker", "image", "inspect", "-f", "{{.Id}}", IMAGE], text=True
    ).strip()
    assert image.startswith("sha256:")
    return image


def _http(runtime: DockerRuntime, url: str) -> str:
    script = (
        "import urllib.error, urllib.request\n"
        f"req = urllib.request.Request({url!r})\n"
        "try:\n"
        "    print(urllib.request.urlopen(req, timeout=10).read().decode())\n"
        "except urllib.error.HTTPError as exc:\n"
        "    print(exc.read().decode())\n"
        "except OSError as exc:\n"
        "    print(type(exc).__name__)\n"
    )
    result = runtime.exec(["python3", "-B", "-"], script)
    return result.text


def test_docker_sandbox_reaches_the_fixture_only_through_the_proxy():
    """Container flags via docker inspect, direct egress blocked, proxy path works."""
    _build()
    with _serve() as port:
        target = Target(
            base_url="http://fixture.test",
            scope=Scope(
                allowed_domains=["fixture.test"],
                rate_limit_rps=1000,
                max_requests=20,
            ),
        )
        proxy = ScopeProxy(
            target,
            NetworkPolicy(allow_private=True),
            resolver=_resolver(),
        )
        runtime = DockerRuntime()
        try:
            proxy.start(runtime.bind_host)
            host_port = urlsplit(proxy.url).port
            runtime.start(
                RuntimeSpec(
                    name="haris-agent-job-itest",
                    proxy_url=proxy.client_url("proxy:8080"),
                    image=IMAGE,
                    upstream=f"host.docker.internal:{host_port}",
                )
            )
            info = runtime.inspect()
            host = info["HostConfig"]
            print("INSPECT_USER", info["Config"].get("User"))
            print("INSPECT_READONLY", host.get("ReadonlyRootfs"))
            print("INSPECT_CAPDROP", host.get("CapDrop"))
            print("INSPECT_SECOPT", host.get("SecurityOpt"))
            print("INSPECT_PIDS", host.get("PidsLimit"))
            print("INSPECT_MEMORY", host.get("Memory"))
            print("INSPECT_NANOCPUS", host.get("NanoCpus"))
            print("INSPECT_PRIVILEGED", host.get("Privileged"))
            print("INSPECT_NETWORK", host.get("NetworkMode"))
            print("INSPECT_BINDS", host.get("Binds"))
            print("INSPECT_MOUNTS", info.get("Mounts"))
            print("INSPECT_TMPFS", host.get("Tmpfs"))
            env = info["Config"].get("Env") or []
            print(
                "INSPECT_ENV",
                [item.replace(proxy.token, "[REDACTED]") for item in env],
            )
            assert info["Config"].get("User") == "65534:65534"
            assert host.get("ReadonlyRootfs") is True
            # Podman lists dropped caps one by one in inspect; read the effective set
            caps = runtime.exec(["python3", "-B", "-"], CAPS)
            assert caps.text.strip() == "0" * 16
            assert any(
                "no-new-privileges" in item for item in (host.get("SecurityOpt") or [])
            )
            assert host.get("PidsLimit") == 128
            assert host.get("Memory") == 512 * 1024 * 1024
            assert host.get("NanoCpus") == 1_000_000_000
            assert host.get("Privileged") is False
            assert host.get("NetworkMode") != "host"
            assert not host.get("Binds")
            tmpfs = host.get("Tmpfs") or {}
            assert "/work" in tmpfs and "/tmp" in tmpfs
            assert all(
                "docker.sock" not in str(item) for item in info.get("Mounts") or []
            )
            assert all("sk-" not in item for item in env)
            assert any(
                item.startswith("HTTP_PROXY=http://job:") and "@proxy:8080" in item
                for item in env
            )
            tunnel = subprocess.check_output(
                ["docker", "inspect", runtime._tunnel], text=True
            )
            assert proxy.token not in tunnel
            direct = runtime.exec(["python3", "-B", "-"], DIRECT)
            assert "connected" not in direct.text
            page = _http(runtime, f"http://fixture.test:{port}/ping")
            assert "pong" in page
            blocked = _http(runtime, "http://evil.test/steal")
            assert "rejected: scope" in blocked
        finally:
            runtime.stop()
            proxy.close()
    left = subprocess.run(
        ["docker", "ps", "-aq", "--filter", "name=haris-agent-"],
        text=True,
        capture_output=True,
        check=True,
    )
    assert left.stdout.strip() == ""
    networks = subprocess.run(
        ["docker", "network", "ls", "--filter", "name=haris-agent-", "-q"],
        text=True,
        capture_output=True,
        check=True,
    )
    assert networks.stdout.strip() == ""
