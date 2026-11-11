import sqlite3

from yoyo import step

__depends__ = {"0007_job_queue"}


def apply(conn: sqlite3.Connection) -> None:
    conn.execute("ALTER TABLE scans ADD COLUMN stage_log TEXT NOT NULL DEFAULT '[]'")
    conn.execute(
        "ALTER TABLE findings ADD COLUMN agent_annotation TEXT NOT NULL DEFAULT ''"
    )


def rollback(conn: sqlite3.Connection) -> None:
    conn.execute("ALTER TABLE findings DROP COLUMN agent_annotation")
    conn.execute("ALTER TABLE scans DROP COLUMN stage_log")


step(apply, rollback)
