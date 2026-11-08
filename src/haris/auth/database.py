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

    def _connect(self) -> AbstractContextManager[sqlite3.Connection, bool | None]:
        return connect(self._db_path)
