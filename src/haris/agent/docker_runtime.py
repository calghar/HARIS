import json
import logging
import select
import subprocess
import threading
import time
from typing import IO, Any

from pydantic import BaseModel

from .runtime import RuntimeSpec, SandboxRuntime, container_argv
from .settings import AgentSettings, load_agent_settings

logger = logging.getLogger(__name__)

PREFIX = "haris-agent-"
EXEC_TIMEOUT_S = 30
EXEC_OUTPUT_CAP_BYTES = 1_048_576  # stored stdout+stderr; anything past this is killed
PROBE_TIMEOUT_S = 10  # a hung daemon must not block web submit
# Print the pid, then replace the process so a timeout can kill it inside the container.
_PID_LINE = (
    "import os, sys\n"
    "print(os.getpid(), flush=True)\n"
    "try:\n"
    "    os.setsid()\n"
    "except OSError:\n"
    "    pass\n"
    "os.execvp(sys.argv[1], sys.argv[1:])\n"
)
_KILL_GROUP = (
    "import os, signal, sys\n"
    "pid = int(sys.argv[1])\n"
    "try:\n"
    "    os.killpg(pid, signal.SIGKILL)\n"
    "except OSError:\n"
    "    os.kill(pid, signal.SIGKILL)\n"
)


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
        ["docker", "image", "inspect", "-f", "{{.Id}}", image],
        text=True,
        timeout=PROBE_TIMEOUT_S,
    ).strip()
    if not out.startswith("sha256:"):
        raise RuntimeError(f"{image} has no image digest")
    return out


def sandbox_available(image: str | None = None) -> bool:
    """True when Docker returns a digest for the sandbox image."""
    chosen = load_agent_settings().image if image is None else image
    try:
        image_id(chosen)
    except (OSError, subprocess.SubprocessError, RuntimeError):
        return False
    return True


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


def _pid_argv(argv: list[str]) -> list[str]:
    return ["python3", "-B", "-c", _PID_LINE, *argv]


def _write_stdin(proc: subprocess.Popen[bytes], data: bytes) -> None:
    stdin = proc.stdin
    if stdin is None:
        return
    try:
        stdin.write(data)
        stdin.close()
    except (BrokenPipeError, OSError, ValueError):
        return


def _read_line(stream: IO[bytes], deadline: float) -> bytes:
    buf = bytearray()
    while time.monotonic() < deadline and len(buf) < 32:
        remaining = max(0.0, deadline - time.monotonic())
        ready, _, _ = select.select([stream], [], [], remaining)
        if not ready:
            break
        piece = stream.read(1)
        if not piece:
            break
        buf += piece
        if piece == b"\n":
            break
    return bytes(buf)


def _collect(
    proc: subprocess.Popen[bytes], cap: int, timeout_s: float
) -> tuple[str, bytes, bytes, bool, bool]:
    stdout, stderr = proc.stdout, proc.stderr
    if stdout is None or stderr is None:
        raise RuntimeError("exec pipes were not created")
    deadline = time.monotonic() + timeout_s
    pid = _read_line(stdout, deadline).strip().decode("ascii", "replace")
    if not pid.isdecimal():
        pid = ""
    out, err = bytearray(), bytearray()
    done = {stdout: False, stderr: False}
    buffers = {stdout: out, stderr: err}
    timed_out = False
    while not all(done.values()):
        if len(out) + len(err) >= cap:
            break
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            timed_out = True
            break
        open_streams = [stream for stream, finished in done.items() if not finished]
        ready, _, _ = select.select(open_streams, [], [], remaining)
        if not ready:
            timed_out = proc.poll() is None
            break
        for stream in ready:
            room = cap - (len(out) + len(err))
            if room <= 0:
                break
            chunk = stream.read(room)
            if not chunk:
                done[stream] = True
                continue
            buffers[stream] += chunk
    truncated = len(out) + len(err) >= cap and not all(done.values())
    return pid, bytes(out), bytes(err), timed_out, truncated


def _kill_pid(sandbox: str, pid: str) -> None:
    if not pid.isdecimal():
        return
    try:
        subprocess.run(
            ["docker", "exec", sandbox, "python3", "-B", "-c", _KILL_GROUP, pid],
            capture_output=True,
            timeout=PROBE_TIMEOUT_S,
        )
    except (OSError, subprocess.SubprocessError):
        logger.warning("sandbox process %s was not killed", pid)


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
        proc: subprocess.Popen[bytes] = subprocess.Popen(
            ["docker", "exec", "-i", self._sandbox, *_pid_argv(argv)],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            bufsize=0,
        )
        feeder = threading.Thread(
            target=_write_stdin, args=(proc, stdin.encode()), daemon=True
        )
        feeder.start()
        try:
            pid, out, err, timed_out, truncated = _collect(
                proc, EXEC_OUTPUT_CAP_BYTES, EXEC_TIMEOUT_S
            )
        finally:
            feeder.join(timeout=PROBE_TIMEOUT_S)
        if timed_out or truncated:
            _kill_pid(self._sandbox, pid)
            proc.kill()
        try:
            proc.wait(timeout=PROBE_TIMEOUT_S)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=PROBE_TIMEOUT_S)
        if timed_out:
            raise subprocess.TimeoutExpired(proc.args, EXEC_TIMEOUT_S)
        text = out.decode("utf-8", "replace")
        if proc.returncode != 0:
            text = err.decode("utf-8", "replace") or text
        return ExecResult(ok=proc.returncode == 0 and not truncated, text=text)

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
