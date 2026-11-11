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


def _kill_script(argv: list[str]) -> str:
    return argv[argv.index("-c") + 1]


def _run(
    monkeypatch: pytest.MonkeyPatch,
    stdout: bytes,
    *,
    close_stdout: bool,
    kill_status: int | BaseException = 0,
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
        if isinstance(kill_status, BaseException):
            raise kill_status
        return subprocess.CompletedProcess(argv, kill_status)

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
    assert runtime.unusable is False
    script = _kill_script(runs[0])
    assert "os.listdir('/proc')" in script
    assert "os.kill" in script
    assert "--user" in runs[0]
    assert "42" not in runs[0]


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
    assert runtime.unusable is False
    assert "os.listdir('/proc')" in _kill_script(runs[0])
    assert "7" not in runs[0]


@pytest.mark.parametrize(
    "kill_status",
    [1, subprocess.TimeoutExpired(["docker", "exec"], 1)],
)
def test_l1_cleanup_failure_marks_the_sandbox_unusable(
    monkeypatch: pytest.MonkeyPatch, kill_status: int | BaseException
) -> None:
    monkeypatch.setattr("haris.agent.docker_runtime.EXEC_OUTPUT_CAP_BYTES", 8)
    runtime, procs, runs, _writes = _run(
        monkeypatch, b"42\n" + b"x" * 40, close_stdout=True, kill_status=kill_status
    )
    with pytest.raises(RuntimeError, match="unusable"):
        runtime.exec(USER_ARGV)
    assert runtime.unusable is True
    assert procs[0].killed is True
    assert "os.listdir('/proc')" in _kill_script(runs[0])
    with pytest.raises(RuntimeError, match="unusable"):
        runtime.exec(USER_ARGV)
    assert len(procs) == 1
    assert len(runs) == 1
