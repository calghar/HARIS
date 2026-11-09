import threading
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

from haris.db.jobs import JobStatus
from haris.models import ScanSession, ScanState, Target
from haris.web.job_queue import FAILURE_ERROR
from haris.web.scan_runtime import AUTH_LOST_ERROR

from .test_web_env import WebEnv, wait_for
from .web_helpers import cancel, job_status, start_scan, status


class RecordingRunner:
    """Replaces `ScanRunner`: records its arguments and returns a canned session."""

    instances: list["RecordingRunner"] = []
    fail = False

    def __init__(self, **kwargs: Any) -> None:
        self.kwargs = kwargs
        self.cancelled = threading.Event()
        self.hold = False
        RecordingRunner.instances.append(self)

    def cancel(self) -> None:
        self.cancelled.set()

    def run(self) -> ScanSession:
        if RecordingRunner.fail:
            raise RuntimeError("scanner exploded")
        target: Target = self.kwargs["target"]
        partial = ScanSession(
            session_id=self.kwargs["session_id"],
            target=target,
            started_at="2026-01-02T03:04:05+00:00",
            scan_state=ScanState.RUNNING,
        )
        self.kwargs["checkpoint"](partial)
        if self.hold:
            self.cancelled.wait(30)
        state = ScanState.CANCELLED if self.cancelled.is_set() else ScanState.COMPLETED
        return ScanSession(
            session_id=self.kwargs["session_id"],
            target=target,
            started_at="2026-01-02T03:04:05+00:00",
            finished_at="2026-01-02T03:05:05+00:00",
            profile_name=self.kwargs["profile_name"],
            scan_state=state,
        )


@pytest.fixture()
def real_execute(monkeypatch: pytest.MonkeyPatch) -> Iterator[type[RecordingRunner]]:
    RecordingRunner.instances = []
    RecordingRunner.fail = False
    monkeypatch.setattr("haris.web.scan_runtime.ScanRunner", RecordingRunner)
    yield RecordingRunner


def test_execute_scan_wires_the_runner_and_persists_the_session(
    tmp_path: Path, real_execute: type[RecordingRunner]
) -> None:
    env = WebEnv(tmp_path)
    template = env.add_template(env.alice)
    scan_id = start_scan(
        env,
        profile="standard",
        report_formats="json",
        auth_method="header",
        auth_header_value="Bearer s3cret-credential",
        excluded_paths="/logout\n/admin",
        rate_limit="3",
        max_requests="50",
        template_id=template,
    )
    wait_for(lambda: status(env, scan_id) == "completed")
    runner = real_execute.instances[0]
    kwargs = runner.kwargs
    assert kwargs["session_id"] == scan_id
    assert kwargs["profile_name"] == "standard"
    assert kwargs["network_policy"].allow_private is False
    target: Target = kwargs["target"]
    assert target.base_url == "https://app.example.com"
    assert target.auth.header_value == "Bearer s3cret-credential"
    assert target.scope.excluded_paths == ["/logout", "/admin"]
    assert (target.scope.rate_limit_rps, target.scope.max_requests) == (3.0, 50)
    assert scan_id not in env.state.scan_credentials
    assert env.state.store.scan_owner(scan_id) == env.alice.user_id
    record = env.state.store.get_scan_record(scan_id)
    assert record is not None
    assert (record["template_id"], record["profile_name"]) == (template, "standard")
    assert list(env.settings.reports_dir.glob(f"report_app.example.com_{scan_id}.json"))
    wait_for(lambda: job_status(env, scan_id) is JobStatus.COMPLETED)


def test_execute_scan_checkpoints_keep_owner_and_profile(
    tmp_path: Path, real_execute: type[RecordingRunner]
) -> None:
    env = WebEnv(tmp_path)
    saved: list[tuple[str, str, str]] = []
    original = env.state.store.save_session

    def spy(session: ScanSession, owner_user_id: str = "") -> None:
        saved.append((session.scan_state.value, session.profile_name, owner_user_id))
        original(session, owner_user_id)

    env.state.store.save_session = spy  # type: ignore[method-assign]
    scan_id = start_scan(env, profile="standard")
    wait_for(lambda: status(env, scan_id) == "completed")
    assert saved[0] == ("running", "standard", env.alice.user_id)
    assert saved[-1][0] == "completed"
    assert env.state.store.scan_owner(scan_id) == env.alice.user_id


def test_cancelling_a_running_scan_stops_the_runner(
    tmp_path: Path, real_execute: type[RecordingRunner], monkeypatch: pytest.MonkeyPatch
) -> None:
    original_init = RecordingRunner.__init__

    def holding(self: RecordingRunner, **kwargs: Any) -> None:
        original_init(self, **kwargs)
        self.hold = True

    monkeypatch.setattr(RecordingRunner, "__init__", holding)
    env = WebEnv(tmp_path)
    scan_id = start_scan(env)
    wait_for(lambda: bool(real_execute.instances))
    assert cancel(env, env.alice, scan_id).status_code == 202
    wait_for(lambda: status(env, scan_id) == "cancelled")
    assert real_execute.instances[0].cancelled.is_set()
    wait_for(lambda: job_status(env, scan_id) is JobStatus.CANCELLED)


def test_scanner_failure_marks_the_scan_failed(
    tmp_path: Path, real_execute: type[RecordingRunner]
) -> None:
    real_execute.fail = True
    env = WebEnv(tmp_path)
    scan_id = start_scan(env)
    wait_for(lambda: status(env, scan_id) == "failed")
    body = env.browser(env.alice).get(f"/api/v1/scans/{scan_id}").json()
    assert body["error"] == FAILURE_ERROR


def test_scan_with_lost_credentials_fails_instead_of_running_unauthenticated(
    tmp_path: Path, real_execute: type[RecordingRunner]
) -> None:
    env = WebEnv(tmp_path)
    scan_id = start_scan(env, auth_method="header", auth_header_value="Bearer x")
    wait_for(lambda: status(env, scan_id) == "completed")
    env.state.scan_credentials.clear()
    lost = "lost0001"
    params = env.state.store.jobs.get(scan_id)
    assert params is not None
    env.state.jobs.submit(
        lost,
        env.alice.user_id,
        params.params,
        target_url="https://app.example.com",
        profile_name="quick",
        template_id="",
    )
    wait_for(lambda: status(env, lost) == "failed")
    assert len(real_execute.instances) == 1
    assert (
        AUTH_LOST_ERROR
        == "Target credentials were not retained across a server restart"
    )
