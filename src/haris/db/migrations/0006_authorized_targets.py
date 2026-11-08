import sqlite3

from yoyo import step

__depends__ = {"0005_api_tokens"}


def apply(conn: sqlite3.Connection) -> None:
    conn.execute(
        """CREATE TABLE authorized_targets (
            user_id     TEXT NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
            host        TEXT NOT NULL,
            proof_token TEXT NOT NULL,
            created_at  TEXT NOT NULL,
            verified_at TEXT NOT NULL DEFAULT '',
            method      TEXT NOT NULL DEFAULT '',
            PRIMARY KEY (user_id, host)
        )"""
    )


def rollback(conn: sqlite3.Connection) -> None:
    conn.execute("DROP TABLE authorized_targets")


step(apply, rollback)
