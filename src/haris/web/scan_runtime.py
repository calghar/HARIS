import logging
import re
from datetime import UTC, datetime
from typing import Any
from urllib.parse import urlparse

from fastapi import HTTPException

from ..auth.models import User
from ..core.runner import ScanRunner
from ..models import ScanSession, Target
from ..reporting import REPORTER_REGISTRY
from .access import Access, require_scan_access, scan_access
from .state import AppState

logger = logging.getLogger(__name__)

SCAN_ID_LENGTH = 10


class ScanStatus:
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


def domain_slug(url: str) -> str:
    """Filesystem-safe hostname for report file names."""
    hostname = urlparse(url).hostname or "unknown"
    return re.sub(r"[^a-zA-Z0-9._-]", "_", hostname)


def load_scan(
    state: AppState, scan_id: str
) -> tuple[dict[str, Any], ScanSession | None]:
    """In-memory scan record, hydrated from the database when not cached."""
    scan = state.scans.get(scan_id)
    if scan:
        return scan, scan.get("session")
    session = state.store.load_session(scan_id)
    if session is None:
        raise HTTPException(status_code=404, detail="Scan not found")
    scan = {
        "scan_id": scan_id,
        "target_url": session.target.base_url,
        "profile": session.profile_name,
        "status": ScanStatus.COMPLETED,
        "started_at": session.started_at,
        "finished_at": session.finished_at,
        "session": session,
        "report_formats": ["markdown", "json", "html"],
        "error": None,
    }
    state.scans[scan_id] = scan
    return scan, session


def get_scan_for_user(
    state: AppState, user: User, scan_id: str
) -> tuple[dict[str, Any], ScanSession | None, Access]:
    """Scan visible to `user`; anything else is a 404."""
    access = require_scan_access(state, user, scan_id)
    scan, session = load_scan(state, scan_id)
    return scan, session, access


def active_scans(
    state: AppState, user: User, statuses: tuple[str, ...]
) -> list[dict[str, Any]]:
    """In-memory scans in the given states that the user may see."""
    return [
        s
        for s in state.scans.values()
        if s["status"] in statuses
        and scan_access(state, user, s["scan_id"]) is not Access.NONE
    ]


def get_completed_session(state: AppState, user: User, scan_id: str) -> ScanSession:
    scan, session, _ = get_scan_for_user(state, user, scan_id)
    if scan["status"] != ScanStatus.COMPLETED or not session:
        raise HTTPException(status_code=404, detail="Scan not found or not complete")
    return session


def run_scan_blocking(
    state: AppState,
    scan_id: str,
    target: Target,
    profile_name: str,
    report_formats: list[str],
    llm_enrich: bool = False,
    llm_backend_name: str | None = None,
    template_id: str = "",
    scanner_options: dict[str, dict[str, Any]] | None = None,
) -> None:
    scan = state.scans[scan_id]
    scan["status"] = ScanStatus.RUNNING

    try:
        runner = ScanRunner(
            target=target,
            profile_name=profile_name,
            session_id=scan_id,
            llm_enrich=llm_enrich,
            llm_backend_name=llm_backend_name,
            scanner_options=scanner_options,
        )
        session = runner.run()
        session.template_id = template_id

        scan["session"] = session
        scan["status"] = ScanStatus.COMPLETED
        scan["finished_at"] = datetime.now(UTC).isoformat()

        try:
            state.store.save_session(session)
            logger.info("Saved session %s to database", scan_id)
        except Exception as db_exc:
            logger.warning("Could not save session to database: %s", db_exc)

        reports_dir = state.settings.reports_dir
        reports_dir.mkdir(parents=True, exist_ok=True)
        domain = domain_slug(target.base_url)
        for fmt in report_formats:
            reporter_cls = REPORTER_REGISTRY.get(fmt)
            if reporter_cls:
                reporter = reporter_cls()
                filename = f"report_{domain}_{scan_id}{reporter.file_extension}"
                reporter.write(session, reports_dir / filename)

    except Exception as exc:
        logger.exception("Scan %s failed", scan_id)
        scan["status"] = ScanStatus.FAILED
        scan["error"] = str(exc)
        scan["finished_at"] = datetime.now(UTC).isoformat()
