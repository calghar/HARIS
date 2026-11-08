import sqlite3

from yoyo import step

__depends__ = {"0004_scan_owner_state"}


def apply(conn: sqlite3.Connection) -> None:
    conn.execute(
        """CREATE TABLE api_tokens (
            token_id     TEXT PRIMARY KEY,
            user_id      TEXT NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
            name         TEXT NOT NULL DEFAULT '',
            token_hash   TEXT NOT NULL UNIQUE,
            token_prefix TEXT NOT NULL,
            scopes       TEXT NOT NULL,
            created_at   TEXT NOT NULL,
            expires_at   TEXT NOT NULL,
            last_used_at TEXT NOT NULL DEFAULT '',
            revoked_at   TEXT NOT NULL DEFAULT ''
        )"""
    )
    conn.execute("CREATE INDEX idx_api_tokens_user ON api_tokens(user_id)")


def rollback(conn: sqlite3.Connection) -> None:
    conn.execute("DROP TABLE api_tokens")


step(apply, rollback)
