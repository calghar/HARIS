import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

BUSY_TIMEOUT_SECONDS = 10


@contextmanager
def connect(db_path: Path) -> Iterator[sqlite3.Connection]:
    conn = sqlite3.connect(db_path, timeout=BUSY_TIMEOUT_SECONDS)
    conn.row_factory = sqlite3.Row
    # foreign_keys is per-connection; WAL is persistent and set once by migrate()
    conn.execute("PRAGMA foreign_keys=ON")
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()
