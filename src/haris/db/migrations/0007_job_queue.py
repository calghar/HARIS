import sqlite3

from yoyo import step

__depends__ = {"0006_authorized_targets"}


def apply(conn: sqlite3.Connection) -> None:
    conn.execute(
        """CREATE TABLE jobs (
            scan_id       TEXT PRIMARY KEY,
            owner_user_id TEXT NOT NULL,
            status        TEXT NOT NULL DEFAULT 'queued',
            params_json   TEXT NOT NULL DEFAULT '{}',
            error         TEXT NOT NULL DEFAULT '',
            worker_id     TEXT NOT NULL DEFAULT '',
            created_at    TEXT NOT NULL,
            started_at    TEXT NOT NULL DEFAULT '',
            finished_at   TEXT NOT NULL DEFAULT ''
        )"""
    )
    conn.execute("CREATE INDEX idx_jobs_status ON jobs(status, created_at)")


def rollback(conn: sqlite3.Connection) -> None:
    conn.execute("DROP TABLE jobs")


step(apply, rollback)
