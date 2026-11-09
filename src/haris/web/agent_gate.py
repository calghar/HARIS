import shutil
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

from fastapi import HTTPException

from ..agent.policy import (
    DISABLED_ENV,
    bind_policy,
    disabled,
    policy_for_web,
    reset_policy,
)
from ..auth.models import User
from ..db.jobs import Job
from ..verify.settings import VerifyMode
from .state import AppState
from .targets import url_host

AGENT_RUNS_DIR = "agent-runs"


def agent_run_dir(state: AppState, scan_id: str) -> Path:
    return state.settings.reports_dir / AGENT_RUNS_DIR / scan_id


def remove_agent_run(state: AppState, scan_id: str) -> None:
    shutil.rmtree(agent_run_dir(state, scan_id), ignore_errors=True)


def effective_verify(state: AppState, verify: VerifyMode | None) -> VerifyMode:
    return state.settings.verify_default if verify is None else verify


def require_agent_allowed(
    state: AppState, user: User, host: str, verify: VerifyMode | None
) -> None:
    """403 unless admin, agent enabled and host proven; 422 when verify is off."""
    if not user.is_admin:
        raise HTTPException(status_code=403, detail="The agent requires the admin role")
    if disabled():
        raise HTTPException(
            status_code=403, detail=f"The agent is disabled ({DISABLED_ENV}=1)"
        )
    if not state.targets.has_verified_proof(user.user_id, host):
        raise HTTPException(
            status_code=403,
            detail="The agent needs a verified ownership proof for this host",
        )
    if effective_verify(state, verify) is VerifyMode.OFF:
        raise HTTPException(
            status_code=422, detail="The agent runs inside verification; verify is off"
        )


def _skip_reason(
    state: AppState, is_admin: bool, authorised: bool, verify: VerifyMode | None
) -> str:
    if not is_admin:
        return "owner is no longer an active admin"
    if disabled():
        return f"{DISABLED_ENV}=1"
    if not authorised:
        return "no current verified ownership proof for the host"
    if effective_verify(state, verify) is VerifyMode.OFF:
        return "verify is off"
    return ""


@contextmanager
def agent_policy(
    state: AppState, job: Job, requested: bool, verify: VerifyMode | None
) -> Iterator[str]:
    """Bind the web agent policy on the scan thread; yields the skip reason or ''."""
    if not requested:
        yield ""
        return
    owner = state.auth.get_user_by_id(job.owner_user_id)
    is_admin = owner is not None and owner.is_active and owner.is_admin
    authorised = state.targets.has_verified_proof(
        job.owner_user_id, url_host(str(job.params["target_url"]))
    )
    reason = _skip_reason(state, is_admin, authorised, verify)
    policy = (
        None
        if reason
        else policy_for_web(
            is_admin=is_admin,
            target_authorised=authorised,
            output_dir=str(agent_run_dir(state, job.scan_id)),
        )
    )
    if policy is None:
        yield reason or f"{DISABLED_ENV}=1"
        return
    token = bind_policy(policy)
    try:
        yield ""
    finally:
        reset_policy(token)
