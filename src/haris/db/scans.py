import logging
from pathlib import Path
from typing import Any

from ..models import ScanSession
from .connection import connect
from .session_read import read_session
from .session_write import write_session

logger = logging.getLogger(__name__)

_SUMMARY_COLUMNS = (
    "s.session_id, s.target_url, s.profile_name, s.started_at,"
    " s.risk_posture, s.template_id, COUNT(f.id) AS finding_count"
)


def _summary(row: Any) -> dict[str, Any]:
    return {
        "session_id": row["session_id"],
        "target_url": row["target_url"],
        "profile_name": row["profile_name"],
        "started_at": row["started_at"],
        "risk_posture": row["risk_posture"],
        "finding_count": row["finding_count"],
        "template_id": row["template_id"],
    }


class ScanRepository:
    def __init__(self, db_path: Path) -> None:
        self._db_path = db_path

    def save_session(self, session: ScanSession) -> None:
        with connect(self._db_path) as conn:
            write_session(conn, session)
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

    def list_sessions(self) -> list[dict[str, Any]]:
        with connect(self._db_path) as conn:
            rows = conn.execute(
                f"""SELECT {_SUMMARY_COLUMNS}
                    FROM scans s
                    LEFT JOIN findings f ON f.session_id = s.session_id
                    GROUP BY s.session_id
                    ORDER BY s.started_at DESC"""  # nosec B608
            ).fetchall()
        return [_summary(row) for row in rows]

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
    ) -> tuple[list[dict[str, Any]], int]:
        where_clauses: list[str] = []
        params: list[Any] = []
        if hostname:
            where_clauses.append("s.target_url LIKE ?")
            params.append(f"%{hostname}%")
        if date_from:
            where_clauses.append("s.started_at >= ?")
            params.append(date_from)
        if date_to:
            where_clauses.append("s.started_at <= ?")
            params.append(date_to + "T23:59:59")
        if severity:
            where_clauses.append(
                """EXISTS (SELECT 1 FROM findings f2
                          WHERE f2.session_id = s.session_id
                          AND f2.severity = ?)"""
            )
            params.append(severity)
        if template_id:
            where_clauses.append("s.template_id = ?")
            params.append(template_id)
        if scanner:
            where_clauses.append("s.scanners_used LIKE ?")
            params.append(f'%"{scanner}"%')

        base = """FROM scans s
                  LEFT JOIN findings f ON f.session_id = s.session_id"""
        where_sql = " WHERE " + " AND ".join(where_clauses) if where_clauses else ""

        with connect(self._db_path) as conn:
            total = conn.execute(
                f"SELECT COUNT(DISTINCT s.session_id) AS c {base}{where_sql}",  # nosec B608
                params,
            ).fetchone()["c"]
            rows = conn.execute(
                f"""SELECT {_SUMMARY_COLUMNS}
                    {base}{where_sql}
                    GROUP BY s.session_id
                    ORDER BY s.started_at DESC
                    LIMIT ? OFFSET ?""",  # nosec B608
                [*params, per_page, (page - 1) * per_page],
            ).fetchall()
        return [_summary(row) for row in rows], total
