from pathlib import Path
from typing import Any

from pydantic import BaseModel

from .connection import connect


class AuthorizedTarget(BaseModel):
    user_id: str
    host: str
    proof_token: str
    created_at: str
    verified_at: str = ""
    method: str = ""


def _target(row: Any) -> AuthorizedTarget:
    return AuthorizedTarget(
        user_id=row["user_id"],
        host=row["host"],
        proof_token=row["proof_token"],
        created_at=row["created_at"],
        verified_at=row["verified_at"],
        method=row["method"],
    )


class TargetRepository:
    def __init__(self, db_path: Path) -> None:
        self._db_path = db_path

    def add(self, user_id: str, host: str, proof_token: str, now: str) -> bool:
        """Create the row with its proof token; False when it already exists."""
        with connect(self._db_path) as conn:
            cursor = conn.execute(
                "INSERT OR IGNORE INTO authorized_targets"
                " (user_id, host, proof_token, created_at) VALUES (?, ?, ?, ?)",
                (user_id, host, proof_token, now),
            )
            return cursor.rowcount > 0

    def get(self, user_id: str, host: str) -> AuthorizedTarget | None:
        with connect(self._db_path) as conn:
            row = conn.execute(
                "SELECT * FROM authorized_targets WHERE user_id = ? AND host = ?",
                (user_id, host),
            ).fetchone()
        return _target(row) if row else None

    def list_for_user(self, user_id: str) -> list[AuthorizedTarget]:
        with connect(self._db_path) as conn:
            rows = conn.execute(
                "SELECT * FROM authorized_targets WHERE user_id = ? ORDER BY host",
                (user_id,),
            ).fetchall()
        return [_target(row) for row in rows]

    def mark_verified(self, user_id: str, host: str, method: str, now: str) -> None:
        with connect(self._db_path) as conn:
            conn.execute(
                "UPDATE authorized_targets SET verified_at = ?, method = ?"
                " WHERE user_id = ? AND host = ?",
                (now, method, user_id, host),
            )

    def delete(self, user_id: str, host: str) -> bool:
        with connect(self._db_path) as conn:
            cursor = conn.execute(
                "DELETE FROM authorized_targets WHERE user_id = ? AND host = ?",
                (user_id, host),
            )
            return cursor.rowcount > 0
