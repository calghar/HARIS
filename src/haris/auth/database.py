import sqlite3
from contextlib import AbstractContextManager
from datetime import UTC, datetime, timedelta
from pathlib import Path

from ..db.connection import connect
from ..db.migrate import migrate


def now_iso() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds")


def future_iso(*, hours: int = 0, days: int = 0) -> str:
    delta = timedelta(hours=hours, days=days)
    return (datetime.now(UTC) + delta).isoformat(timespec="seconds")


class SqliteService:
    def __init__(self, db_path: str | Path = "data/HARIS.db") -> None:
        self._db_path = Path(db_path)
        migrate(self._db_path)
        self._ensure_auth_schema()

    def _connect(self) -> AbstractContextManager[sqlite3.Connection, bool | None]:
        return connect(self._db_path)

    def _ensure_auth_schema(self) -> None:
        """Add auth columns. Existing rows keep the default of 0."""
        with self._connect() as conn:
            cols = {row[1] for row in conn.execute("PRAGMA table_info(users)")}
            if "disabled_by_admin" not in cols:
                conn.execute(
                    "ALTER TABLE users ADD COLUMN disabled_by_admin"
                    " INTEGER NOT NULL DEFAULT 0"
                )
            conn.execute(
                """CREATE TABLE IF NOT EXISTS auth_attempt_counters (
                    bucket TEXT PRIMARY KEY,
                    attempts INTEGER NOT NULL,
                    window_started REAL NOT NULL
                )"""
            )
            conn.execute(
                """CREATE TABLE IF NOT EXISTS instance_bootstrap (
                    id INTEGER PRIMARY KEY CHECK (id = 1),
                    created_at TEXT NOT NULL
                )"""
            )
