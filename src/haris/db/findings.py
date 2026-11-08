from pathlib import Path
from typing import Any

from .connection import connect


class FindingRepository:
    def __init__(self, db_path: Path) -> None:
        self._db_path = db_path

    def get_findings(
        self,
        session_id: str,
        *,
        severity: str | None = None,
        owasp_category: str | None = None,
    ) -> list[dict[str, Any]]:
        query = "SELECT * FROM findings WHERE session_id = ?"
        params: list[Any] = [session_id]
        if severity:
            query += " AND severity = ?"
            params.append(severity)
        if owasp_category:
            query += " AND owasp_category LIKE ?"
            params.append(f"%{owasp_category}%")
        query += " ORDER BY id"

        with connect(self._db_path) as conn:
            rows = conn.execute(query, params).fetchall()
        return [
            {
                key: row[key]
                for key in (
                    "finding_id",
                    "title",
                    "description",
                    "severity",
                    "confidence",
                    "owasp_category",
                    "cwe_id",
                    "url",
                    "parameter",
                    "scanner",
                    "remediation",
                )
            }
            for row in rows
        ]
