import json
from collections.abc import Callable
from pathlib import Path

import pytest

from haris.auth.models import AuditAction, User
from haris.web.job_queue import CancelToken
from haris.web.scan_runtime import execute_scan

from .test_web_agent import PolicyRunner, _admin_with_proof, _stored_job
from .test_web_env import WebEnv, stub_scan_runner
from .web_helpers import HOST, scan_count, start, verified

NOTE = "[agent] skipped: docker unavailable"
Setup = tuple[User, dict[str, str]]
Prepare = Callable[[WebEnv, pytest.MonkeyPatch], Setup]


def _down() -> bool:
    return False


def _up() -> bool:
    return True


def _refusals(env: WebEnv) -> list[dict[str, object]]:
    return [
        row
        for row in env.state.auth.get_audit_log(limit=50)
        if row["action"] == AuditAction.AGENT_REFUSED.value
    ]


def _as_user(env: WebEnv, _: pytest.MonkeyPatch) -> Setup:
    verified(env, env.alice, HOST, days_ago=1)
    return env.alice, {}


def _no_proof(env: WebEnv, _: pytest.MonkeyPatch) -> Setup:
    return env.admin, {}


def _disabled(env: WebEnv, patch: pytest.MonkeyPatch) -> Setup:
    verified(env, env.admin, HOST, days_ago=1)
    patch.setenv("HARIS_AGENT_DISABLED", "1")
    return env.admin, {}


def _verify_off(env: WebEnv, _: pytest.MonkeyPatch) -> Setup:
    verified(env, env.admin, HOST, days_ago=1)
    return env.admin, {"verify": "off"}


@pytest.mark.parametrize(
    ("prepare", "status_code", "reason"),
    [
        (_as_user, 403, "not_admin"),
        (_no_proof, 403, "no_verified_proof"),
        (_disabled, 403, "agent_disabled"),
        (_verify_off, 422, "verify_off"),
    ],
)
def test_each_refusal_writes_one_audit_row(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    prepare: Prepare,
    status_code: int,
    reason: str,
) -> None:
    stub_scan_runner(monkeypatch)
    env = WebEnv(tmp_path)
    user, extra = prepare(env, monkeypatch)
    before = scan_count(env)
    response = start(env, user, agent="1", **extra)
    assert response.status_code == status_code
    assert scan_count(env) == before
    (row,) = _refusals(env)
    assert row["user_id"] == user.user_id
    assert row["resource_id"] == ""
    details = json.loads(str(row["details_json"]))
    assert details == {"host": HOST, "reason": reason}


def test_submit_skips_the_agent_when_docker_is_unavailable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr("haris.agent.docker_runtime.sandbox_available", _down)
    env = _admin_with_proof(tmp_path, monkeypatch)
    response = start(env, env.admin, agent="1")
    assert response.status_code == 202, response.text
    body = response.json()
    assert body["notes"] == [NOTE]
    scan_id = body["scan_id"]
    job = env.state.store.jobs.get(scan_id)
    assert job is not None
    assert job.params["agent"] is False
    record = env.state.store.get_scan_record(scan_id)
    assert record is not None
    assert NOTE in record["errors"]
    session = env.state.store.load_session(scan_id)
    assert session is not None
    assert NOTE in session.errors
    assert NOTE in session.stage_log
    assert _refusals(env) == []


def _prepare_runner(monkeypatch: pytest.MonkeyPatch) -> None:
    PolicyRunner.instances = []
    PolicyRunner.seen = []
    PolicyRunner.explode = False
    PolicyRunner.fail = False
    monkeypatch.setattr("haris.web.scan_runtime.ScanRunner", PolicyRunner)


def test_runtime_probe_failure_records_the_note_in_stage_log_and_errors(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr("haris.agent.docker_runtime.sandbox_available", _up)
    _prepare_runner(monkeypatch)
    env = _admin_with_proof(tmp_path, monkeypatch)
    job = _stored_job(env)
    assert job.params["agent"] is True
    monkeypatch.setattr("haris.agent.docker_runtime.sandbox_available", _down)
    execute_scan(env.state, job, CancelToken())
    assert PolicyRunner.seen == [None]
    session = env.state.store.load_session(job.scan_id)
    assert session is not None
    assert NOTE in session.errors
    assert NOTE in session.stage_log


def test_runtime_probe_success_binds_policy_and_skips_the_docker_note(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr("haris.agent.docker_runtime.sandbox_available", _up)
    _prepare_runner(monkeypatch)
    env = _admin_with_proof(tmp_path, monkeypatch)
    job = _stored_job(env)
    execute_scan(env.state, job, CancelToken())
    assert PolicyRunner.seen[0] is not None
    session = env.state.store.load_session(job.scan_id)
    assert session is not None
    assert NOTE not in session.errors
    assert NOTE not in session.stage_log
