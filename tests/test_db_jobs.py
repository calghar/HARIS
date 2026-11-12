import json
from pathlib import Path

import pytest

from haris.db.connection import connect
from haris.db.jobs import JobRepository, JobStatus
from haris.db.migrate import migrate
from haris.db.store import ScanStore
from haris.models import ScanSession, ScanState, Target

NOTE = "[agent] skipped: docker unavailable"
PRIOR = "[agent] skipped: image missing"
_OWNER = "user-1"
_NOW = "2026-11-11T19:00:00+00:00"


def _repo(tmp_path: Path) -> tuple[JobRepository, Path]:
    db = tmp_path / "jobs.db"
    migrate(db)
    return JobRepository(db), db


def _enqueue(repo: JobRepository, scan_id: str) -> None:
    repo.enqueue(
        scan_id,
        _OWNER,
        {"agent": False},
        target_url="https://example.com",
        profile_name="full",
        template_id="builtin-01",
        now=_NOW,
    )


def _columns(db: Path, scan_id: str) -> tuple[str, str] | None:
    with connect(db) as conn:
        row = conn.execute(
            "SELECT errors, stage_log FROM scans WHERE session_id = ?",
            (scan_id,),
        ).fetchone()
    if row is None:
        return None
    return str(row["errors"]), str(row["stage_log"])


@pytest.mark.parametrize("prior", [None, PRIOR])
def test_keep_skip_note_replaces_errors_and_stage_log(
    tmp_path: Path, prior: str | None
) -> None:
    repo, db = _repo(tmp_path)
    _enqueue(repo, "scan-9f3a")
    if prior is not None:
        existing = json.dumps([prior])
        with connect(db) as conn:
            conn.execute(
                "UPDATE scans SET errors = ?, stage_log = ? WHERE session_id = ?",
                (existing, existing, "scan-9f3a"),
            )
    repo.keep_skip_note("scan-9f3a", NOTE)
    stored = json.dumps([NOTE])
    assert _columns(db, "scan-9f3a") == (stored, stored)
    repo.keep_skip_note("scan-9f3a", NOTE)
    assert _columns(db, "scan-9f3a") == (stored, stored)


def test_keep_skip_note_does_not_create_a_missing_scan(tmp_path: Path) -> None:
    repo, db = _repo(tmp_path)
    repo.keep_skip_note("missing-scan", NOTE)
    assert _columns(db, "missing-scan") is None


@pytest.mark.parametrize(
    "note",
    [
        "[verify] llm verdict skipped: no LLM backend",
        "[verify] 2 finding(s) not replayed: verify.max_requests reached",
    ],
)
def test_failed_scan_keeps_its_skip_notes(tmp_path: Path, note: str) -> None:
    """Scenario: Failed scan keeps its notes."""
    store = ScanStore(tmp_path / "failed.db")
    _enqueue(store.jobs, "scan-1c7e")
    store.jobs.claim_next("worker-1", _NOW)
    store.save_session(
        ScanSession(
            session_id="scan-1c7e",
            target=Target(base_url="https://example.com"),
            errors=[note],
            scan_state=ScanState.RUNNING,
        ),
        _OWNER,
    )
    store.jobs.finish("scan-1c7e", JobStatus.FAILED, _NOW, "The scan failed.")
    loaded = store.load_session("scan-1c7e")
    assert loaded is not None
    assert loaded.scan_state is ScanState.FAILED
    assert loaded.errors == ["The scan failed.", note]
