import logging
import time
from collections.abc import Iterator
from pathlib import Path

import pytest

from haris.auth.cookies import SESSION_COOKIE
from haris.db.connection import connect
from haris.db.jobs import JobStatus
from haris.web.app import create_app
from haris.web.job_queue import FAILURE_ERROR, RESTART_ERROR

from .test_web_env import Browser, FakeRunner, WebEnv, stub_scan_runner, wait_for
from .web_helpers import SETTLE_S, cancel, job_status, start_scan, status


@pytest.fixture()
def runner(monkeypatch: pytest.MonkeyPatch) -> Iterator[FakeRunner]:
    fake = stub_scan_runner(monkeypatch, block=True)
    yield fake
    fake.release()


def test_started_scan_is_persisted_as_queued_then_running(
    tmp_path: Path, runner: FakeRunner
) -> None:
    env = WebEnv(tmp_path, max_concurrent=1)
    first, second = start_scan(env), start_scan(env)
    runner.wait_started()
    assert status(env, first) == "running"
    assert status(env, second) == "pending"
    assert job_status(env, first) is JobStatus.RUNNING
    assert job_status(env, second) is JobStatus.QUEUED


def test_concurrency_never_exceeds_the_configured_bound(
    tmp_path: Path, runner: FakeRunner
) -> None:
    env = WebEnv(tmp_path, max_concurrent=2)
    ids = [start_scan(env) for _ in range(5)]
    runner.wait_started(2)
    time.sleep(SETTLE_S)
    assert len(runner.started) == 2
    assert env.state.jobs.running_count == 2
    assert sorted(status(env, i) for i in ids) == ["pending"] * 3 + ["running"] * 2
    runner.release()
    wait_for(lambda: all(status(env, i) == "completed" for i in ids))
    assert runner.peak == 2
    assert sorted(runner.started) == sorted(ids)


def test_queue_runs_jobs_in_submission_order(
    tmp_path: Path, runner: FakeRunner
) -> None:
    env = WebEnv(tmp_path, max_concurrent=1)
    ids = [start_scan(env) for _ in range(4)]
    runner.release()
    wait_for(lambda: all(status(env, i) == "completed" for i in ids))
    assert runner.started == ids


def test_cancel_queued_job(tmp_path: Path, runner: FakeRunner) -> None:
    env = WebEnv(tmp_path, max_concurrent=1)
    running, queued = start_scan(env), start_scan(env)
    runner.wait_started()
    response = cancel(env, env.alice, queued)
    assert response.status_code == 202
    assert response.json() == {"scan_id": queued, "status": "cancelled"}
    assert job_status(env, queued) is JobStatus.CANCELLED
    assert status(env, queued) == "cancelled"
    runner.release()
    wait_for(lambda: status(env, running) == "completed")
    time.sleep(SETTLE_S)
    assert runner.started == [running]
    assert job_status(env, queued) is JobStatus.CANCELLED


def test_cancel_running_job_frees_the_slot(tmp_path: Path, runner: FakeRunner) -> None:
    env = WebEnv(tmp_path, max_concurrent=1)
    running, waiting = start_scan(env), start_scan(env)
    runner.wait_started()
    assert cancel(env, env.alice, running).status_code == 202
    wait_for(lambda: status(env, running) == "cancelled")
    wait_for(lambda: job_status(env, running) is JobStatus.CANCELLED)
    runner.wait_started(2)
    assert runner.started == [running, waiting]
    assert status(env, waiting) == "running"


def test_cancel_of_a_finished_scan_is_a_conflict(
    tmp_path: Path, runner: FakeRunner
) -> None:
    env = WebEnv(tmp_path)
    done = env.add_scan(env.alice)
    assert cancel(env, env.alice, done).status_code == 409
    scan_id = start_scan(env)
    runner.release()
    wait_for(lambda: status(env, scan_id) == "completed")
    assert cancel(env, env.alice, scan_id).status_code == 409


def test_cancel_needs_ownership(tmp_path: Path, runner: FakeRunner) -> None:
    env = WebEnv(tmp_path, share_scans=True)
    scan_id = start_scan(env)
    assert cancel(env, env.bob, scan_id).status_code == 403
    assert cancel(env, env.admin, scan_id).status_code == 202
    (tmp_path / "private").mkdir()
    private = WebEnv(tmp_path / "private")
    other = start_scan(private)
    assert cancel(private, private.bob, other).status_code == 404


def test_queued_and_running_scans_cannot_be_deleted(
    tmp_path: Path, runner: FakeRunner
) -> None:
    env = WebEnv(tmp_path, max_concurrent=1)
    running, queued = start_scan(env), start_scan(env)
    runner.wait_started()
    alice = env.browser(env.alice)
    for scan_id in (running, queued):
        response = alice.delete(f"/api/v1/scans/{scan_id}", headers=alice.csrf_headers)
        assert response.status_code == 409
    cancel(env, env.alice, queued)
    deleted = alice.delete(f"/api/v1/scans/{queued}", headers=alice.csrf_headers)
    assert deleted.status_code == 204
    assert env.state.store.jobs.get(queued) is None


def test_restart_marks_running_jobs_incomplete_and_resumes_queued_ones(
    tmp_path: Path, runner: FakeRunner
) -> None:
    env = WebEnv(tmp_path, max_concurrent=1)
    dead, waiting = start_scan(env), start_scan(env)
    runner.wait_started()
    assert job_status(env, waiting) is JobStatus.QUEUED

    restarted = create_app(env.settings).state.haris
    record = restarted.store.get_scan_record(dead)
    assert record["scan_state"] == "incomplete"
    assert record["errors"] == [RESTART_ERROR]
    job = restarted.store.jobs.get(dead)
    assert job is not None
    assert (job.status, job.error) == (JobStatus.INCOMPLETE, RESTART_ERROR)
    queued = restarted.store.jobs.get(waiting)
    assert queued is not None
    assert queued.status is JobStatus.QUEUED

    env.state.jobs.shutdown()
    restarted.jobs.dispatch()
    wait_for(lambda: waiting in runner.started)
    restarted.jobs.shutdown()


def test_restart_does_not_touch_finished_jobs(
    tmp_path: Path, runner: FakeRunner
) -> None:
    env = WebEnv(tmp_path)
    scan_id = start_scan(env)
    runner.release()
    wait_for(lambda: status(env, scan_id) == "completed")
    restarted = create_app(env.settings).state.haris
    record = restarted.store.get_scan_record(scan_id)
    assert record["scan_state"] == "completed"
    assert record["errors"] == []


def test_incomplete_scan_is_visible_through_the_api(
    tmp_path: Path, runner: FakeRunner
) -> None:
    env = WebEnv(tmp_path)
    scan_id = start_scan(env)
    runner.wait_started()
    app = create_app(env.settings)
    client = Browser(app)
    token = env.state.auth.create_session(env.alice.user_id).token
    client.cookies.set(SESSION_COOKIE, token)
    body = client.get(f"/api/v1/scans/{scan_id}").json()
    assert body["status"] == "incomplete"
    assert body["error"] == RESTART_ERROR
    assert client.get(f"/scan/{scan_id}").status_code == 200


def test_runner_exception_fails_the_job_with_a_generic_message(
    tmp_path: Path, runner: FakeRunner, caplog: pytest.LogCaptureFixture
) -> None:
    runner.error = "database password hunter2"
    env = WebEnv(tmp_path)
    scan_id = start_scan(env)
    runner.release()
    with caplog.at_level(logging.ERROR):
        wait_for(lambda: status(env, scan_id) == "failed")
    body = env.browser(env.alice).get(f"/api/v1/scans/{scan_id}")
    assert body.json()["error"] == FAILURE_ERROR
    assert "hunter2" not in body.text
    assert "hunter2" in caplog.text
    assert "hunter2" not in env.browser(env.alice).get(f"/scan/{scan_id}").text


def test_target_credentials_are_never_written_to_the_database(
    tmp_path: Path, runner: FakeRunner
) -> None:
    env = WebEnv(tmp_path)
    scan_id = start_scan(
        env, auth_method="header", auth_header_value="Bearer s3cret-credential"
    )
    runner.wait_started()
    with connect(env.settings.db_path) as conn:
        dump = "\n".join(conn.iterdump())
    assert "s3cret-credential" not in dump
    assert env.state.scan_credentials[scan_id] == "Bearer s3cret-credential"
