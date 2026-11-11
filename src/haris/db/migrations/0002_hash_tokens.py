import sqlite3

from yoyo import step

from haris.auth.tokens import hash_token

__depends__ = {"0001_baseline"}

TOKEN_TABLES = ("user_sessions", "remember_tokens", "email_verifications")


def hash_existing_tokens(conn: sqlite3.Connection) -> None:
    for table in TOKEN_TABLES:
        stored = [row[0] for row in conn.execute(f"SELECT token FROM {table}")]  # nosec B608
        conn.executemany(
            f"UPDATE {table} SET token = ? WHERE token = ?",  # nosec B608
            [(hash_token(token), token) for token in stored],
        )


step(hash_existing_tokens)
