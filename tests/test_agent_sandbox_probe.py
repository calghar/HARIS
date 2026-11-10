import subprocess
from collections.abc import Callable

import pytest

import haris.agent.docker_runtime as docker_runtime


def _raise(exc: Exception) -> Callable[[str], str]:
    def probe(image: str) -> str:
        raise exc

    return probe


@pytest.mark.parametrize(
    "failure",
    [
        FileNotFoundError("docker"),
        subprocess.CalledProcessError(1, "docker"),
        subprocess.TimeoutExpired("docker", docker_runtime.PROBE_TIMEOUT_S),
        RuntimeError("no image digest"),
    ],
)
def test_sandbox_is_unavailable_when_the_probe_fails(
    monkeypatch: pytest.MonkeyPatch, failure: Exception
) -> None:
    monkeypatch.setattr(docker_runtime, "image_id", _raise(failure))
    assert docker_runtime.sandbox_available("haris-agent-sandbox:test") is False


def test_sandbox_is_available_when_docker_returns_a_digest(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(docker_runtime, "image_id", lambda image: "sha256:abc")
    assert docker_runtime.sandbox_available("haris-agent-sandbox:test") is True


def test_image_probe_is_bounded(monkeypatch: pytest.MonkeyPatch) -> None:
    seen: dict[str, object] = {}

    def fake(argv: list[str], **kwargs: object) -> str:
        seen.update(kwargs)
        return "sha256:abc\n"

    monkeypatch.setattr(docker_runtime.subprocess, "check_output", fake)
    docker_runtime.image_id("haris-agent-sandbox:test")
    assert seen["timeout"] == docker_runtime.PROBE_TIMEOUT_S
