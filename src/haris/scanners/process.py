import contextlib
import os
import signal
import subprocess

TERM_GRACE_SECONDS = 2.0
DRAIN_SECONDS = 5.0


class ToolTimeoutError(RuntimeError):
    def __init__(self, message: str, stdout: str, stderr: str) -> None:
        super().__init__(message)
        self.stdout = stdout
        self.stderr = stderr


def _text(value: str | bytes | None) -> str:
    if isinstance(value, bytes):
        return value.decode(errors="replace")
    return value or ""


def _signal_group(pid: int, sig: signal.Signals) -> None:
    # macOS answers EPERM for a group that only holds zombies.
    with contextlib.suppress(ProcessLookupError, PermissionError):
        os.killpg(pid, sig)


def _stop_group(proc: subprocess.Popen[str]) -> tuple[str, str]:
    """Stop the child's whole process group and return the output so far."""
    out, err = "", ""
    _signal_group(proc.pid, signal.SIGTERM)
    with contextlib.suppress(subprocess.TimeoutExpired):
        out, err = proc.communicate(timeout=TERM_GRACE_SECONDS)
    _signal_group(proc.pid, signal.SIGKILL)
    try:
        out, err = proc.communicate(timeout=DRAIN_SECONDS)
    except subprocess.TimeoutExpired as exc:
        out, err = _text(exc.stdout), _text(exc.stderr)
    return out, err


def run_process(cmd: list[str], timeout: float) -> tuple[int, str, str]:
    """Run *cmd* in its own session; on timeout kill the group, keep partial output."""
    proc = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        start_new_session=True,
    )
    try:
        stdout, stderr = proc.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        stdout, stderr = _stop_group(proc)
        raise ToolTimeoutError(f"timed out after {timeout}s", stdout, stderr) from None
    except BaseException:
        _stop_group(proc)
        raise
    return proc.returncode, stdout, stderr
