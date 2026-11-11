import json
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any

import pytest

from haris.agent.policy import AgentPolicy, current_policy
from haris.auth.models import UserRole
from haris.db.jobs import Job
from haris.models import ScanSession
from haris.verify import VerifyMode
from haris.web.job_queue import CancelToken
from haris.web.scan_runtime import execute_scan

from .test_web_env import WebEnv, stub_scan_runner, wait_for
from .test_web_execute import RecordingRunner
from .web_helpers import HOST, scan_count, start, status, verified


class PolicyRunner(RecordingRunner):
    """Records the agent policy visible on the thread that calls `run()`."""

    seen: list[AgentPolicy | None] = []
    explode = False

    def run(self) -> ScanSession:
        PolicyRunner.seen.append(current_policy())
        if PolicyRunner.explode:
            raise RuntimeError("scanner exploded")
        return super().run()


def _docker_up() -> bool:
    return True


@pytest.fixture(autouse=True)
def agent_enabled(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("HARIS_AGENT_DISABLED", raising=False)
    monkeypatch.setattr("haris.agent.docker_runtime.sandbox_available", _docker_up)


@pytest.fixture()
def policy_runner(monkeypatch: pytest.MonkeyPatch) -> Iterator[type[PolicyRunner]]:
    PolicyRunner.instances = []
    PolicyRunner.seen = []
    PolicyRunner.explode = False
    PolicyRunner.fail = False
    monkeypatch.setattr("haris.web.scan_runtime.ScanRunner", PolicyRunner)
    yield PolicyRunner


def _agent_start(env: WebEnv, user: Any = None, **extra: str) -> Any:
    return start(env, user or env.admin, agent="1", **extra)


def _params(env: WebEnv, scan_id: str) -> dict[str, Any]:
    job = env.state.store.jobs.get(scan_id)
    assert job is not None
    return job.params


def _admin_with_proof(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> WebEnv:
    """Environment whose scans are stored but never executed by the queue."""
    stub_scan_runner(monkeypatch)
    env = WebEnv(tmp_path)
    verified(env, env.admin, HOST, days_ago=1)
    return env


def _stored_job(env: WebEnv, **extra: str) -> Job:
    response = _agent_start(env, **extra)
    assert response.status_code == 202, response.text
    job = env.state.store.jobs.get(response.json()["scan_id"])
    assert job is not None
    return job


def test_admin_with_a_current_proof_starts_an_agent_scan(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Admin plus a current proof row: 202 and the stored job params carry agent."""
    env = _admin_with_proof(tmp_path, monkeypatch)
    response = _agent_start(env)
    assert response.status_code == 202, response.text
    assert _params(env, response.json()["scan_id"])["agent"] is True


def test_scan_without_the_agent_field_is_unchanged(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    env = _admin_with_proof(tmp_path, monkeypatch)
    response = start(env, env.admin)
    assert response.status_code == 202
    assert _params(env, response.json()["scan_id"])["agent"] is False


def test_non_admin_is_refused_and_no_scan_is_created(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    env = _admin_with_proof(tmp_path, monkeypatch)
    verified(env, env.alice, HOST, days_ago=1)
    before = scan_count(env)
    response = _agent_start(env, env.alice)
    assert response.status_code == 403
    assert "admin" in response.json()["detail"]
    assert scan_count(env) == before


def test_allow_list_match_alone_is_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    stub_scan_runner(monkeypatch)
    env = WebEnv(tmp_path)
    before = scan_count(env)
    response = _agent_start(env)
    assert response.status_code == 403
    assert "ownership proof" in response.json()["detail"]
    assert scan_count(env) == before


def test_proof_older_than_30_days_is_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    stub_scan_runner(monkeypatch)
    env = WebEnv(tmp_path)
    verified(env, env.admin, HOST, days_ago=31)
    before = scan_count(env)
    assert _agent_start(env).status_code == 403
    assert scan_count(env) == before


def test_agent_disabled_variable_is_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    env = _admin_with_proof(tmp_path, monkeypatch)
    monkeypatch.setenv("HARIS_AGENT_DISABLED", "1")
    before = scan_count(env)
    response = _agent_start(env)
    assert response.status_code == 403
    assert "HARIS_AGENT_DISABLED" in response.json()["detail"]
    assert scan_count(env) == before


def test_verify_off_is_a_422(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    env = _admin_with_proof(tmp_path, monkeypatch)
    before = scan_count(env)
    assert _agent_start(env, verify="off").status_code == 422
    assert scan_count(env) == before


def test_server_default_verify_off_is_a_422(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    env = _admin_with_proof(tmp_path, monkeypatch)
    env.settings.verify_default = VerifyMode.OFF
    assert _agent_start(env).status_code == 422


def test_policy_is_bound_in_the_worker_thread_for_the_run(
    tmp_path: Path, policy_runner: type[PolicyRunner]
) -> None:
    """The queue thread sees a web policy with unsafe methods off and a scan dir."""
    env = WebEnv(tmp_path)
    verified(env, env.admin, HOST, days_ago=1)
    response = _agent_start(env)
    scan_id = response.json()["scan_id"]
    wait_for(lambda: status(env, scan_id) == "completed")
    (policy,) = policy_runner.seen
    assert policy is not None
    assert policy.source == "web"
    assert policy.allow_unsafe_methods is False
    assert policy.output_dir == str(env.settings.reports_dir / "agent-runs" / scan_id)


def test_scan_without_agent_binds_no_policy(
    tmp_path: Path, policy_runner: type[PolicyRunner]
) -> None:
    env = WebEnv(tmp_path)
    scan_id = start(env, env.admin).json()["scan_id"]
    wait_for(lambda: status(env, scan_id) == "completed")
    assert policy_runner.seen == [None]


def test_policy_is_reset_after_execute_scan_returns(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, policy_runner: type[PolicyRunner]
) -> None:
    env = _admin_with_proof(tmp_path, monkeypatch)
    job = _stored_job(env)
    execute_scan(env.state, job, CancelToken())
    assert policy_runner.seen[0] is not None
    assert current_policy() is None


def test_policy_is_reset_when_run_raises(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, policy_runner: type[PolicyRunner]
) -> None:
    env = _admin_with_proof(tmp_path, monkeypatch)
    job = _stored_job(env)
    policy_runner.explode = True
    with pytest.raises(RuntimeError, match="exploded"):
        execute_scan(env.state, job, CancelToken())
    assert policy_runner.seen[0] is not None
    assert current_policy() is None


def _demote(env: WebEnv, _: pytest.MonkeyPatch) -> None:
    env.state.auth.update_user(env.admin.user_id, role=UserRole.USER.value)


def _expire(env: WebEnv, _: pytest.MonkeyPatch) -> None:
    env.state.store.targets.mark_verified(
        env.admin.user_id, HOST, "dns", "2020-01-01T00:00:00+00:00"
    )


def _disable(_: WebEnv, patch: pytest.MonkeyPatch) -> None:
    patch.setenv("HARIS_AGENT_DISABLED", "1")


@pytest.mark.parametrize(
    ("change", "reason"),
    [
        (_demote, "no longer an active admin"),
        (_expire, "verified ownership proof"),
        (_disable, "HARIS_AGENT_DISABLED=1"),
    ],
)
def test_run_time_recheck_skips_the_agent_and_records_why(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    policy_runner: type[PolicyRunner],
    change: Callable[[WebEnv, pytest.MonkeyPatch], None],
    reason: str,
) -> None:
    env = _admin_with_proof(tmp_path, monkeypatch)
    job = _stored_job(env)
    change(env, monkeypatch)
    execute_scan(env.state, job, CancelToken())
    assert policy_runner.seen == [None]
    session = env.state.store.load_session(job.scan_id)
    assert session is not None
    (error,) = [e for e in session.errors if e.startswith("[agent] skipped:")]
    assert reason in error


def test_delete_scan_removes_the_agent_run_directory(
    tmp_path: Path, policy_runner: type[PolicyRunner]
) -> None:
    env = WebEnv(tmp_path)
    verified(env, env.admin, HOST, days_ago=1)
    scan_id = _agent_start(env).json()["scan_id"]
    wait_for(lambda: status(env, scan_id) == "completed")
    run_dir = env.settings.reports_dir / "agent-runs" / scan_id / "agent" / "j1"
    run_dir.mkdir(parents=True)
    (run_dir / "audit.jsonl").write_text("{}\n")
    client = env.browser(env.admin)
    response = client.delete(f"/api/v1/scans/{scan_id}", headers=client.csrf_headers)
    assert response.status_code == 204
    assert not (env.settings.reports_dir / "agent-runs" / scan_id).exists()


def test_scan_form_offers_the_agent_checkbox_to_an_admin(tmp_path: Path) -> None:
    env = WebEnv(tmp_path)
    html = env.browser(env.admin).get("/scan/new").text
    assert 'name="agent"' in html


def test_scan_form_hides_the_agent_checkbox_from_a_user(tmp_path: Path) -> None:
    env = WebEnv(tmp_path)
    html = env.browser(env.alice).get("/scan/new").text
    assert 'name="agent"' not in html


def test_start_audit_entry_records_the_agent_flag(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    env = _admin_with_proof(tmp_path, monkeypatch)
    scan_id = _agent_start(env).json()["scan_id"]
    events = env.state.auth.get_audit_log(limit=20)
    started = [e for e in events if e["resource_id"] == scan_id]
    assert json.loads(started[0]["details_json"])["agent"] is True
