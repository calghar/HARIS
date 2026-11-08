import sqlite3

from yoyo import step

__depends__ = {"0003_finding_identity"}

SCAN_COLUMNS = (
    ("owner_user_id", "TEXT NOT NULL DEFAULT ''"),
    ("scan_state", "TEXT NOT NULL DEFAULT 'completed'"),
    ("scanner_status", "TEXT NOT NULL DEFAULT '{}'"),
    ("correlated_json", "TEXT NOT NULL DEFAULT '[]'"),
)


def apply(conn: sqlite3.Connection) -> None:
    for name, definition in SCAN_COLUMNS:
        conn.execute(f"ALTER TABLE scans ADD COLUMN {name} {definition}")  # nosec B608
    conn.execute("UPDATE scans SET owner_user_id = started_by")
    conn.execute("CREATE INDEX idx_scans_owner ON scans(owner_user_id)")
    conn.execute(
        "ALTER TABLE scan_config_templates"
        " ADD COLUMN owner_user_id TEXT NOT NULL DEFAULT ''"
    )


def rollback(conn: sqlite3.Connection) -> None:
    conn.execute("ALTER TABLE scan_config_templates DROP COLUMN owner_user_id")
    conn.execute("DROP INDEX idx_scans_owner")
    for name, _ in reversed(SCAN_COLUMNS):
        conn.execute(f"ALTER TABLE scans DROP COLUMN {name}")  # nosec B608


step(apply, rollback)
