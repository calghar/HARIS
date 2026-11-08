from pathlib import Path
from typing import Any

from pydantic import BaseModel

from .connection import connect


class ApiTokenRecord(BaseModel):
    token_id: str
    user_id: str
    name: str
    token_prefix: str
    scopes: list[str]
    created_at: str
    expires_at: str
    last_used_at: str = ""
    revoked_at: str = ""


def _record(row: Any) -> ApiTokenRecord:
    return ApiTokenRecord(
        token_id=row["token_id"],
        user_id=row["user_id"],
        name=row["name"],
        token_prefix=row["token_prefix"],
        scopes=row["scopes"].split(","),
        created_at=row["created_at"],
        expires_at=row["expires_at"],
        last_used_at=row["last_used_at"],
        revoked_at=row["revoked_at"],
    )


class ApiTokenRepository:
    def __init__(self, db_path: Path) -> None:
        self._db_path = db_path

    def insert(self, record: ApiTokenRecord, token_hash: str) -> None:
        with connect(self._db_path) as conn:
            conn.execute(
                "INSERT INTO api_tokens (token_id, user_id, name, token_hash,"
                " token_prefix, scopes, created_at, expires_at)"
                " VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    record.token_id,
                    record.user_id,
                    record.name,
                    token_hash,
                    record.token_prefix,
                    ",".join(record.scopes),
                    record.created_at,
                    record.expires_at,
                ),
            )

    def get_by_hash(self, token_hash: str) -> ApiTokenRecord | None:
        with connect(self._db_path) as conn:
            row = conn.execute(
                "SELECT * FROM api_tokens WHERE token_hash = ?", (token_hash,)
            ).fetchone()
        return _record(row) if row else None

    def list_for_user(self, user_id: str) -> list[ApiTokenRecord]:
        with connect(self._db_path) as conn:
            rows = conn.execute(
                "SELECT * FROM api_tokens WHERE user_id = ? ORDER BY created_at DESC",
                (user_id,),
            ).fetchall()
        return [_record(row) for row in rows]

    def revoke(self, token_id: str, user_id: str, now: str) -> bool:
        with connect(self._db_path) as conn:
            cursor = conn.execute(
                "UPDATE api_tokens SET revoked_at = ?"
                " WHERE token_id = ? AND user_id = ? AND revoked_at = ''",
                (now, token_id, user_id),
            )
            return cursor.rowcount > 0

    def touch(self, token_id: str, now: str) -> None:
        with connect(self._db_path) as conn:
            conn.execute(
                "UPDATE api_tokens SET last_used_at = ? WHERE token_id = ?",
                (now, token_id),
            )
