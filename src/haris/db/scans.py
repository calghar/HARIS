import json
import logging
from pathlib import Path
from typing import Any

from ..models import ScanSession, ScanState
from .connection import connect
from .session_read import read_session
from .session_write import write_session

logger = logging.getLogger(__name__)

ALL_ROWS = -1
_SUMMARY_COLUMNS = (
    "s.session_id, s.target_url, s.profile_name, s.started_at, s.finished_at,"
    " s.risk_posture, s.template_id, s.scan_state, s.owner_user_id,"
    " s.scanner_status, s.errors, COUNT(f.id) AS finding_count"
)
_FROM = """FROM scans s LEFT JOIN findings f ON f.session_id = s.session_id"""


def _summary(row: Any) -> dict[str, Any]:
    return {
        "session_id": row["session_id"],
        "target_url": row["target_url"],
        "profile_name": row["profile_name"],
        "started_at": row["started_at"],
        "finished_at": row["finished_at"],
        "risk_posture": row["risk_posture"],
        "finding_count": row["finding_count"],
        "template_id": row["template_id"],
        "scan_state": row["scan_state"],
        "owner_user_id": row["owner_user_id"],
        "scanner_status": json.loads(row["scanner_status"]),
        "errors": json.loads(row["errors"]),
    }


class ScanRepository:
    def __init__(self, db_path: Path) -> None:
        self._db_path = db_path

    def save_session(self, session: ScanSession, owner_user_id: str = "") -> None:
        with connect(self._db_path) as conn:
            write_session(conn, session, owner_user_id)
        logger.info(
            "Saved session %s (%d findings, %d remediation steps)",
            session.session_id,
            len(session.all_findings),
            len(session.remediation_steps),
        )

    def load_session(self, session_id: str) -> ScanSession | None:
        with connect(self._db_path) as conn:
            return read_session(conn, session_id)

    def delete_session(self, session_id: str) -> bool:
        with connect(self._db_path) as conn:
            conn.execute("DELETE FROM jobs WHERE scan_id = ?", (session_id,))
            cursor = conn.execute(
                "DELETE FROM scans WHERE session_id = ?", (session_id,)
            )
            return cursor.rowcount > 0

    def session_exists(self, session_id: str) -> bool:
        with connect(self._db_path) as conn:
            row = conn.execute(
                "SELECT 1 FROM scans WHERE session_id = ? LIMIT 1", (session_id,)
            ).fetchone()
            return row is not None

    def get_record(self, session_id: str) -> dict[str, Any] | None:
        """Summary row of one scan, owner and state included."""
        with connect(self._db_path) as conn:
            row = conn.execute(
                f"""SELECT {_SUMMARY_COLUMNS} {_FROM}
                    WHERE s.session_id = ? GROUP BY s.session_id""",  # nosec B608
                (session_id,),
            ).fetchone()
        return _summary(row) if row else None

    def scan_owner(self, session_id: str) -> str | None:
        """Owner user id ('' when unowned); None when the scan does not exist."""
        with connect(self._db_path) as conn:
            row = conn.execute(
                "SELECT owner_user_id FROM scans WHERE session_id = ?", (session_id,)
            ).fetchone()
        return None if row is None else str(row["owner_user_id"])

    def set_state(self, session_id: str, state: ScanState, error: str = "") -> None:
        """Move a scan row through queue states; an error replaces the error list."""
        with connect(self._db_path) as conn:
            conn.execute(
                "UPDATE scans SET scan_state = ?,"
                " errors = CASE WHEN ? = '' THEN errors ELSE ? END"
                " WHERE session_id = ?",
                (state.value, error, json.dumps([error]), session_id),
            )

    def list_sessions(self, owner_user_id: str | None = None) -> list[dict[str, Any]]:
        rows, _ = self.list_sessions_paginated(
            per_page=ALL_ROWS, owner_user_id=owner_user_id
        )
        return rows

    def list_sessions_paginated(
        self,
        *,
        page: int = 1,
        per_page: int = 20,
        hostname: str | None = None,
        severity: str | None = None,
        date_from: str | None = None,
        date_to: str | None = None,
        template_id: str | None = None,
        scanner: str | None = None,
        owner_user_id: str | None = None,
    ) -> tuple[list[dict[str, Any]], int]:
        """Filtered page of scans; ``owner_user_id=None`` means every owner."""
        clauses: list[str] = []
        params: list[Any] = []
        if owner_user_id is not None:
            clauses.append("s.owner_user_id = ?")
            params.append(owner_user_id)
        if hostname:
            clauses.append("s.target_url LIKE ?")
            params.append(f"%{hostname}%")
        if date_from:
            clauses.append("s.started_at >= ?")
            params.append(date_from)
        if date_to:
            clauses.append("s.started_at <= ?")
            params.append(date_to + "T23:59:59")
        if severity:
            clauses.append(
                """EXISTS (SELECT 1 FROM findings f2
                          WHERE f2.session_id = s.session_id
                          AND f2.severity = ?)"""
            )
            params.append(severity)
        if template_id:
            clauses.append("s.template_id = ?")
            params.append(template_id)
        if scanner:
            clauses.append("s.scanners_used LIKE ?")
            params.append(f'%"{scanner}"%')
        where_sql = " WHERE " + " AND ".join(clauses) if clauses else ""
        offset = (page - 1) * per_page if per_page > 0 else 0

        with connect(self._db_path) as conn:
            total = conn.execute(
                f"SELECT COUNT(DISTINCT s.session_id) AS c {_FROM}{where_sql}",  # nosec B608
                params,
            ).fetchone()["c"]
            rows = conn.execute(
                f"""SELECT {_SUMMARY_COLUMNS} {_FROM}{where_sql}
                    GROUP BY s.session_id
                    ORDER BY s.started_at DESC
                    LIMIT ? OFFSET ?""",  # nosec B608
                [*params, per_page, offset],
            ).fetchall()
        return [_summary(row) for row in rows], total
