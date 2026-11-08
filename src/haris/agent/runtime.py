import abc

from pydantic import BaseModel, Field

from .proxy import fetch_via_proxy
from .settings import AgentSettings


class RuntimeSpec(BaseModel):
    name: str
    proxy_url: str
    image: str = ""
    network: str = ""
    upstream: str = ""
    api_keys: list[str] = Field(default_factory=list)


class SandboxRuntime(abc.ABC):
    """Where a job's tool calls run. Docker is the real one; tests use the fake."""

    bind_host: str = "127.0.0.1"
    tunneled: bool = False

    @abc.abstractmethod
    def start(self, spec: RuntimeSpec) -> None: ...

    @abc.abstractmethod
    def call(self, tool: str, arguments: dict[str, str]) -> str: ...

    @abc.abstractmethod
    def kill(self) -> None: ...

    @abc.abstractmethod
    def stop(self) -> None: ...

    @property
    @abc.abstractmethod
    def calls(self) -> list[tuple[str, dict[str, str]]]: ...


class FakeRuntime(SandboxRuntime):
    """In-memory tools. HTTP is performed by the caller through the proxy."""

    def __init__(self) -> None:
        self._calls: list[tuple[str, dict[str, str]]] = []
        self.files: dict[str, str] = {}
        self.killed = False
        self.started = False
        self.spec: RuntimeSpec | None = None

    def start(self, spec: RuntimeSpec) -> None:
        self.started = True
        self.spec = spec

    def call(self, tool: str, arguments: dict[str, str]) -> str:
        self._calls.append((tool, dict(arguments)))
        if tool == "http_request":
            if self.spec is None:
                return "rejected: proxy"
            _status, text = fetch_via_proxy(
                self.spec.proxy_url,
                arguments.get("method", "GET"),
                arguments.get("url", ""),
                arguments.get("body", ""),
            )
            return text
        if tool == "read_file":
            return self.files.get(arguments.get("path", ""), "")
        if tool == "write_file":
            self.files[arguments.get("path", "")] = arguments.get("content", "")
            return "wrote"
        if tool == "run_python":
            return "ok"
        return ""

    def kill(self) -> None:
        self.killed = True

    def stop(self) -> None:
        self.started = False

    @property
    def calls(self) -> list[tuple[str, dict[str, str]]]:
        return self._calls


def container_argv(spec: RuntimeSpec, settings: AgentSettings) -> list[str]:
    """``docker run`` argv for one job. No host mounts, no inherited environment."""
    network = spec.network or "none"
    if network == "host":
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
        f"/work:rw,size={settings.work_tmpfs}",
        "--tmpfs",
        f"/tmp:rw,size={settings.tmp_tmpfs}",  # nosec B108 container tmpfs
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges",
        "--pids-limit",
        str(settings.pids_limit),
        "--memory",
        settings.memory,
        "--cpus",
        settings.cpus,
        "--user",
        settings.sandbox_user,
        "--network",
        network,
        "-e",
        f"HTTP_PROXY={spec.proxy_url}",
        "-e",
        f"HTTPS_PROXY={spec.proxy_url}",
        "-e",
        "NO_PROXY=",
        "-e",
        "PYTHONDONTWRITEBYTECODE=1",
        "-e",
        "HOME=/tmp",
        spec.image,
        "python3",
        "-B",
        "-c",
        "import time; time.sleep(600)",
    ]
