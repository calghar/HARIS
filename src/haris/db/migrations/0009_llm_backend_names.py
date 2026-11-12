import sqlite3

from yoyo import step

__depends__ = {"0008_agent_fields"}


def apply(conn: sqlite3.Connection) -> None:
    conn.execute(
        "UPDATE scan_config_templates SET llm_backend = 'litellm'"
        " WHERE llm_backend IN ('anthropic', 'openai', 'ollama', 'bedrock')"
    )


def rollback(conn: sqlite3.Connection) -> None:
    # One-way: the original backend names are not recoverable.
    return None


step(apply, rollback)
