import importlib.util
from pathlib import Path
from types import ModuleType

import pytest

TUNNEL = Path(__file__).parents[1] / "docker" / "agent" / "tunnel.py"


def _load() -> ModuleType:
    spec = importlib.util.spec_from_file_location("agent_tunnel", TUNNEL)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class FakeSocket:
    def __init__(self, timeout: float | None) -> None:
        self.timeout = timeout
        self.closed = False

    def settimeout(self, value: float | None) -> None:
        self.timeout = value

    def close(self) -> None:
        self.closed = True


def test_upstream_socket_has_no_read_timeout_after_connect(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The connect timeout must not cut a slow upstream reply."""
    module = _load()
    remote = FakeSocket(timeout=5)
    monkeypatch.setattr(module.socket, "create_connection", lambda *a, **k: remote)
    monkeypatch.setattr(module, "_pipe", lambda source, sink: None)
    monkeypatch.setattr(
        module.threading,
        "Thread",
        lambda **k: type("T", (), {"start": lambda self: None})(),
    )
    module._handle(FakeSocket(timeout=None), "proxy:8080")  # type: ignore[arg-type]
    assert remote.timeout is None
