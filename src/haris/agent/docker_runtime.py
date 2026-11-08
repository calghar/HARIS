import json
import subprocess
from typing import Any

from pydantic import BaseModel

from .runtime import RuntimeSpec, SandboxRuntime, container_argv
from .settings import AgentSettings, load_agent_settings

PREFIX = "haris-agent-"
EXEC_TIMEOUT_S = 30


class ExecResult(BaseModel):
    ok: bool
    text: str


def require_name(name: str) -> str:
    if not name.startswith(PREFIX):
        raise ValueError(f"refusing docker name {name}")
    return name


def image_id(image: str) -> str:
    if image.startswith("sha256:"):
        return image
    out = subprocess.check_output(
        ["docker", "image", "inspect", "-f", "{{.Id}}", image], text=True
    ).strip()
    if not out.startswith("sha256:"):
        raise RuntimeError(f"{image} has no image digest")
    return out


def tunnel_argv(spec: RuntimeSpec, settings: AgentSettings) -> list[str]:
    """Sidecar that forwards the sandbox's proxy port to the host proxy only."""
    if spec.network == "host":
        raise ValueError("refusing host network")
    return [
        "docker",
        "run",
        "-d",
        "--name",
        spec.name,
        "--rm",
        "--read-only",
        "--tmpfs",
        "/tmp:rw,size=16m",  # nosec B108 container tmpfs, not a host path
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges",
        "--pids-limit",
        "64",
        "--memory",
        "128m",
        "--cpus",
        "0.5",
        "--user",
        settings.sandbox_user,
        "--network",
        spec.network,
        "--network-alias",
        "proxy",
        "--add-host",
        "host.docker.internal:host-gateway",
        "-e",
        f"UPSTREAM={spec.upstream}",
        "-e",
        "PYTHONDONTWRITEBYTECODE=1",
        spec.image,
        "python3",
        "-B",
        "/opt/tunnel.py",
    ]


def _wait_tunnel(name: str) -> None:
    """Block until the sidecar accepts connections on its proxy port."""
    script = (
        "import socket, time\n"
        "last = 'down'\n"
        "for _ in range(25):\n"
        "    try:\n"
        "        socket.create_connection(('127.0.0.1', 8080), 0.5).close()\n"
        "        raise SystemExit(0)\n"
        "    except OSError as exc:\n"
        "        last = type(exc).__name__\n"
        "        time.sleep(0.2)\n"
        "raise SystemExit(last)\n"
    )
    proc = subprocess.run(
        ["docker", "exec", "-i", name, "python3", "-B", "-"],
        input=script,
        text=True,
        capture_output=True,
        timeout=EXEC_TIMEOUT_S,
    )
    if proc.returncode != 0:
        raise RuntimeError(proc.stderr.strip() or proc.stdout.strip() or "tunnel down")


def _run(argv: list[str]) -> None:
    proc = subprocess.run(argv, text=True, capture_output=True)
    if proc.returncode != 0:
        raise RuntimeError(proc.stderr.strip() or f"docker exited {proc.returncode}")


class DockerRuntime(SandboxRuntime):
    """One non-root container per job, egress only via the scope proxy."""

    # Colima forwards host.docker.internal to the host loopback, not the LAN.
    bind_host = "127.0.0.1"
    tunneled = True

    def __init__(self, settings: AgentSettings | None = None) -> None:
        self.settings = settings or load_agent_settings()
        self._calls: list[tuple[str, dict[str, str]]] = []
        self._sandbox = ""
        self._tunnel = ""
        self._networks: list[str] = []
        self.killed = False

    def start(self, spec: RuntimeSpec) -> None:
        require_name(spec.name)
        digest = image_id(spec.image)
        suffix = spec.name.removeprefix(PREFIX)
        job = require_name(f"{PREFIX}job-{suffix}")
        egress = require_name(f"{PREFIX}egress-{suffix}")
        self._sandbox = require_name(f"{PREFIX}sbx-{suffix}")
        self._tunnel = require_name(f"{PREFIX}tunnel-{suffix}")
        self._networks = [job, egress]
        _run(["docker", "network", "create", "--internal", job])
        _run(["docker", "network", "create", egress])
        _run(
            tunnel_argv(
                spec.model_copy(
                    update={"name": self._tunnel, "image": digest, "network": job}
                ),
                self.settings,
            )
        )
        _run(["docker", "network", "connect", egress, self._tunnel])
        _wait_tunnel(self._tunnel)
        _run(
            container_argv(
                spec.model_copy(
                    update={
                        "name": self._sandbox,
                        "image": digest,
                        "network": job,
                    }
                ),
                self.settings,
            )
        )

    def call(self, tool: str, arguments: dict[str, str]) -> str:
        self._calls.append((tool, dict(arguments)))
        if tool == "http_request":
            return self.exec(["python3", "-B", "-"], _http_script(arguments)).text
        if tool == "write_file":
            script = (
                "import pathlib\n"
                f"pathlib.Path({arguments.get('path', '')!r})"
                f".write_text({arguments.get('content', '')!r})\n"
            )
            return self.exec(["python3", "-B", "-"], script).text
        if tool == "read_file":
            script = (
                "import pathlib\n"
                f"print(pathlib.Path({arguments.get('path', '')!r}).read_text())\n"
            )
            return self.exec(["python3", "-B", "-"], script).text
        if tool == "run_python":
            return self.exec(["python3", "-B", "-"], arguments.get("script", "")).text
        return ""

    def exec(self, argv: list[str], stdin: str = "") -> ExecResult:
        proc = subprocess.run(
            ["docker", "exec", "-i", self._sandbox, *argv],
            input=stdin,
            text=True,
            capture_output=True,
            timeout=EXEC_TIMEOUT_S,
        )
        text = proc.stdout if proc.returncode == 0 else proc.stderr or proc.stdout
        return ExecResult(ok=proc.returncode == 0, text=text)

    def inspect(self) -> dict[str, Any]:
        raw = subprocess.check_output(["docker", "inspect", self._sandbox], text=True)
        payload: list[dict[str, Any]] = json.loads(raw)
        return payload[0]

    def kill(self) -> None:
        self.killed = True
        for name in (self._sandbox, self._tunnel):
            if name:
                subprocess.run(["docker", "kill", name], capture_output=True)

    def stop(self) -> None:
        for name in (self._sandbox, self._tunnel):
            if name:
                subprocess.run(["docker", "rm", "-f", name], capture_output=True)
        for network in self._networks:
            subprocess.run(["docker", "network", "rm", network], capture_output=True)
        self._sandbox = ""
        self._tunnel = ""
        self._networks = []

    @property
    def calls(self) -> list[tuple[str, dict[str, str]]]:
        return self._calls


def _http_script(arguments: dict[str, str]) -> str:
    method = arguments.get("method", "GET")
    url = arguments.get("url", "")
    body = arguments.get("body", "")
    return (
        "import urllib.error, urllib.request\n"
        f"req = urllib.request.Request({url!r}, data={body.encode()!r} or None, "
        f"method={method!r})\n"
        "try:\n"
        "    resp = urllib.request.urlopen(req, timeout=10)\n"
        "    print(resp.read().decode())\n"
        "except urllib.error.HTTPError as exc:\n"
        "    print(exc.read().decode())\n"
    )
