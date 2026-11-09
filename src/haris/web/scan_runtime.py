import logging
import re
from typing import Any
from urllib.parse import urlparse

from fastapi import HTTPException
from pydantic import BaseModel, Field

from ..auth.models import User
from ..core.runner import ScanRunner
from ..db.jobs import Job, JobStatus
from ..models import AuthConfig, ScanSession, ScanState, Scope, Target
from ..net import NetworkPolicy
from ..reporting import REPORTER_REGISTRY
from ..verify.settings import VerifyMode
from .access import Access, require_scan_access
from .agent_gate import agent_policy
from .job_queue import CancelToken
from .state import AppState

logger = logging.getLogger(__name__)

SCAN_ID_LENGTH = 10
IN_PROGRESS = frozenset({ScanState.PENDING, ScanState.RUNNING})
ERROR_STATES = frozenset({ScanState.FAILED.value, ScanState.INCOMPLETE.value})
FINISHED = frozenset({ScanState.COMPLETED, ScanState.INCOMPLETE, ScanState.CANCELLED})
AUTH_LOST_ERROR = "Target credentials were not retained across a server restart"


class ScanJobParams(BaseModel):
    """Everything a queued scan needs except the target credential (memory only)."""

    target_url: str
    profile_name: str
    report_formats: list[str]
    excluded_paths: list[str] = Field(default_factory=list)
    rate_limit: float
    max_requests: int
    auth_method: str = "none"
    llm_enrich: bool = False
    llm_backend_name: str | None = None
    verify: VerifyMode | None = None  # None: use the server default
    agent: bool = False
    template_id: str = ""
    scanner_options: dict[str, dict[str, Any]] = Field(default_factory=dict)

    def target(self, header_value: str) -> Target:
        return Target(
            base_url=self.target_url,
            scope=Scope(
                excluded_paths=self.excluded_paths,
                rate_limit_rps=self.rate_limit,
                max_requests=self.max_requests,
            ),
            auth=AuthConfig(method=self.auth_method, header_value=header_value),
        )


def domain_slug(url: str) -> str:
    """Filesystem-safe hostname for report file names."""
    hostname = urlparse(url).hostname or "unknown"
    return re.sub(r"[^a-zA-Z0-9._-]", "_", hostname)


def execute_scan(state: AppState, job: Job, token: CancelToken) -> JobStatus:
    """Run one queued scan to completion and persist its session and reports."""
    params = ScanJobParams.model_validate(job.params)
    header_value = state.scan_credentials.pop(job.scan_id, "")
    if params.auth_method != "none" and not header_value:
        raise RuntimeError(AUTH_LOST_ERROR)

    def stamp(session: ScanSession) -> ScanSession:
        session.template_id = params.template_id
        session.profile_name = session.profile_name or params.profile_name
        return session

    def checkpoint(session: ScanSession) -> None:
        state.store.save_session(stamp(session), job.owner_user_id)
        if token.cancelled:
            runner.cancel()

    runner = ScanRunner(
        target=params.target(header_value),
        profile_name=params.profile_name,
        session_id=job.scan_id,
        llm_enrich=params.llm_enrich,
        llm_backend_name=params.llm_backend_name,
        verify=state.settings.verify_default
        if params.verify is None
        else params.verify,
        scanner_options=params.scanner_options,
        network_policy=NetworkPolicy.from_env(),
        checkpoint=checkpoint,
    )
    token.on_cancel(runner.cancel)
    if token.cancelled:
        return JobStatus.CANCELLED
    with agent_policy(state, job, params.agent, params.verify) as skipped:
        session = stamp(runner.run())
    if skipped:
        session.errors.append(f"[agent] skipped: {skipped}")
    state.store.save_session(session, job.owner_user_id)
    write_reports(state, session, params.report_formats)
    try:
        return JobStatus(session.scan_state.value)
    except ValueError:
        return JobStatus.FAILED


def write_reports(
    state: AppState, session: ScanSession, report_formats: list[str]
) -> None:
    reports_dir = state.settings.reports_dir
    reports_dir.mkdir(parents=True, exist_ok=True)
    domain = domain_slug(session.target.base_url)
    for fmt in report_formats:
        reporter_cls = REPORTER_REGISTRY.get(fmt)
        if reporter_cls:
            reporter = reporter_cls()
            filename = f"report_{domain}_{session.session_id}{reporter.file_extension}"
            reporter.write(session, state.settings.reports_dir / filename)


def _record_or_404(state: AppState, scan_id: str) -> dict[str, Any]:
    record = state.store.get_scan_record(scan_id)
    if record is None:
        raise HTTPException(status_code=404, detail="Scan not found")
    return record


def get_scan_record(state: AppState, user: User, scan_id: str) -> dict[str, Any]:
    """Summary row of a scan the user may see; anything else is a 404."""
    require_scan_access(state, user, scan_id)
    return _record_or_404(state, scan_id)


def scan_view(state: AppState, record: dict[str, Any]) -> dict[str, Any]:
    """Record shaped for the scan page template and the status endpoint."""
    job = state.store.jobs.get(record["session_id"])
    status = record["scan_state"]
    return {
        "scan_id": record["session_id"],
        "target_url": record["target_url"],
        "profile": record["profile_name"],
        "status": status,
        "started_at": record["started_at"],
        "finished_at": record["finished_at"] or None,
        "report_formats": list(REPORTER_REGISTRY),
        "llm_enrich": bool(job and job.params.get("llm_enrich")),
        "error": (record["errors"] or [None])[0] if status in ERROR_STATES else None,
    }


def get_scan_for_user(
    state: AppState, user: User, scan_id: str
) -> tuple[dict[str, Any], ScanSession | None, Access]:
    access = require_scan_access(state, user, scan_id)
    record = _record_or_404(state, scan_id)
    return scan_view(state, record), state.store.load_session(scan_id), access


def get_completed_session(state: AppState, user: User, scan_id: str) -> ScanSession:
    """Session of a scan that has finished running (any end state with results)."""
    record = get_scan_record(state, user, scan_id)
    session = state.store.load_session(scan_id)
    if ScanState(record["scan_state"]) not in FINISHED or session is None:
        raise HTTPException(status_code=404, detail="Scan not found or not complete")
    return session
