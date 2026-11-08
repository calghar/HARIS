import json
from enum import StrEnum
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field

from ..models import ScanState
from .connection import connect


class JobStatus(StrEnum):
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"
    INCOMPLETE = "incomplete"

    @property
    def scan_state(self) -> ScanState:
        if self is JobStatus.QUEUED:
            return ScanState.PENDING
        return ScanState(self.value)


class Job(BaseModel):
    scan_id: str
    owner_user_id: str
    status: JobStatus
    params: dict[str, Any] = Field(default_factory=dict)
    error: str = ""
    worker_id: str = ""
    created_at: str
    started_at: str = ""
    finished_at: str = ""


def _job(row: Any) -> Job:
    return Job(
        scan_id=row["scan_id"],
        owner_user_id=row["owner_user_id"],
        status=JobStatus(row["status"]),
        params=json.loads(row["params_json"]),
        error=row["error"],
        worker_id=row["worker_id"],
        created_at=row["created_at"],
        started_at=row["started_at"],
        finished_at=row["finished_at"],
    )


class JobRepository:
    """Job rows and the scan row they drive change state in one transaction."""

    def __init__(self, db_path: Path) -> None:
        self._db_path = db_path

    def enqueue(
        self,
        scan_id: str,
        owner_user_id: str,
        params: dict[str, Any],
        *,
        target_url: str,
        profile_name: str,
        template_id: str,
        now: str,
    ) -> None:
        with connect(self._db_path) as conn:
            conn.execute(
                "INSERT INTO scans (session_id, target_url, profile_name,"
                " started_at, template_id, scan_state, owner_user_id, started_by)"
                " VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    scan_id,
                    target_url,
                    profile_name,
                    now,
                    template_id,
                    ScanState.PENDING.value,
                    owner_user_id,
                    owner_user_id,
                ),
            )
            conn.execute(
                "INSERT INTO jobs (scan_id, owner_user_id, params_json, created_at)"
                " VALUES (?, ?, ?, ?)",
                (scan_id, owner_user_id, json.dumps(params), now),
            )

    def get(self, scan_id: str) -> Job | None:
        with connect(self._db_path) as conn:
            row = conn.execute(
                "SELECT * FROM jobs WHERE scan_id = ?", (scan_id,)
            ).fetchone()
        return _job(row) if row else None

    def claim_next(self, worker_id: str, now: str) -> Job | None:
        """Atomically move the oldest queued job to running."""
        with connect(self._db_path) as conn:
            row = conn.execute(
                """UPDATE jobs SET status = 'running', worker_id = ?, started_at = ?
                   WHERE scan_id = (SELECT scan_id FROM jobs WHERE status = 'queued'
                                    ORDER BY created_at, rowid LIMIT 1)
                   RETURNING *""",
                (worker_id, now),
            ).fetchone()
            if row is None:
                return None
            self._sync_scan(conn, row["scan_id"], JobStatus.RUNNING)
        return _job(row)

    def finish(
        self, scan_id: str, status: JobStatus, now: str, error: str = ""
    ) -> None:
        with connect(self._db_path) as conn:
            conn.execute(
                "UPDATE jobs SET status = ?, finished_at = ?, error = ?"
                " WHERE scan_id = ?",
                (status.value, now, error, scan_id),
            )
            self._sync_scan(conn, scan_id, status, error)

    def cancel_queued(self, scan_id: str, now: str) -> bool:
        """Cancel a job that has not started; False when it already left the queue."""
        with connect(self._db_path) as conn:
            cursor = conn.execute(
                "UPDATE jobs SET status = 'cancelled', finished_at = ?"
                " WHERE scan_id = ? AND status = 'queued'",
                (now, scan_id),
            )
            if cursor.rowcount == 0:
                return False
            self._sync_scan(conn, scan_id, JobStatus.CANCELLED)
            return True

    def recover(self, worker_id: str, now: str, error: str) -> list[str]:
        """Mark running jobs of any other worker incomplete (their process died)."""
        with connect(self._db_path) as conn:
            rows = conn.execute(
                "UPDATE jobs SET status = 'incomplete', finished_at = ?, error = ?"
                " WHERE status = 'running' AND worker_id != ? RETURNING scan_id",
                (now, error, worker_id),
            ).fetchall()
            for row in rows:
                self._sync_scan(conn, row["scan_id"], JobStatus.INCOMPLETE, error)
        return [row["scan_id"] for row in rows]

    @staticmethod
    def _sync_scan(conn: Any, scan_id: str, status: JobStatus, error: str = "") -> None:
        conn.execute(
            "UPDATE scans SET scan_state = ?,"
            " errors = CASE WHEN ? = '' THEN errors ELSE ? END"
            " WHERE session_id = ?",
            (status.scan_state.value, error, json.dumps([error]), scan_id),
        )
