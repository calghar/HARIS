import os
import subprocess

import pytest

from haris.agent.docker_runtime import DockerRuntime
from haris.agent.settings import AgentSettings

USER_ARGV = ["python3", "-B", "-"]


class _Proc:
    def __init__(
        self, args: list[str], stdin: object, stdout: object, stderr: object
    ) -> None:
        self.args = args
        self.stdin = stdin
        self.stdout = stdout
        self.stderr = stderr
        self.returncode: int | None = None
        self.killed = False

    def poll(self) -> int | None:
        return self.returncode

    def kill(self) -> None:
        self.killed = True
        self.returncode = -9

    def wait(self, timeout: float | None = None) -> int:
        if self.returncode is None:
            self.returncode = 0
        return self.returncode


def _run(
    monkeypatch: pytest.MonkeyPatch, stdout: bytes, *, close_stdout: bool
) -> tuple[DockerRuntime, list[_Proc], list[list[str]], list[int]]:
    out_read, out_write = os.pipe()
    err_read, err_write = os.pipe()
    in_read, in_write = os.pipe()
    os.write(out_write, stdout)
    os.close(err_write)
    if close_stdout:
        os.close(out_write)
    procs: list[_Proc] = []
    runs: list[list[str]] = []

    def popen(argv: list[str], **_kwargs: object) -> _Proc:
        proc = _Proc(
            argv,
            os.fdopen(in_write, "wb", buffering=0),
            os.fdopen(out_read, "rb", buffering=0),
            os.fdopen(err_read, "rb", buffering=0),
        )
        procs.append(proc)
        return proc

    def run(argv: list[str], **_kwargs: object) -> subprocess.CompletedProcess[bytes]:
        runs.append(list(argv))
        return subprocess.CompletedProcess(argv, 0)

    monkeypatch.setattr("haris.agent.docker_runtime.subprocess.Popen", popen)
    monkeypatch.setattr("haris.agent.docker_runtime.subprocess.run", run)
    runtime = DockerRuntime(AgentSettings())
    runtime._sandbox = "haris-agent-job"
    os.close(in_read)
    open_writes = [] if close_stdout else [out_write]
    return runtime, procs, runs, open_writes


def test_m5_exec_returns_output_without_the_pid_line(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runtime, procs, runs, _writes = _run(monkeypatch, b"42\nhello\n", close_stdout=True)
    result = runtime.exec(USER_ARGV)
    assert procs[0].args[-3:] == USER_ARGV
    assert result.ok is True
    assert result.text == "hello\n"
    assert runs == []
    assert procs[0].killed is False


def test_m5_exec_caps_output_and_kills_the_inner_process(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("haris.agent.docker_runtime.EXEC_OUTPUT_CAP_BYTES", 8)
    runtime, procs, runs, _writes = _run(
        monkeypatch, b"42\n" + b"x" * 40, close_stdout=True
    )
    result = runtime.exec(USER_ARGV)
    assert result.ok is False
    assert len(result.text.encode()) <= 8
    assert procs[0].killed is True
    assert runs and runs[0][-1] == "42"
    assert "kill" in runs[0][6]


def test_m5_exec_timeout_kills_the_inner_process(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("haris.agent.docker_runtime.EXEC_TIMEOUT_S", 0.4)
    runtime, procs, runs, writes = _run(monkeypatch, b"7\n", close_stdout=False)
    try:
        with pytest.raises(subprocess.TimeoutExpired):
            runtime.exec(USER_ARGV)
    finally:
        for fd in writes:
            os.close(fd)
    assert procs[0].killed is True
    assert runs and runs[0][-1] == "7"
    assert "kill" in runs[0][6]
