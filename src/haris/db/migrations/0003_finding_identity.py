import sqlite3

from yoyo import step

__depends__ = {"0002_hash_tokens"}

OLD_COLUMNS = (
    "id, session_id, finding_id, title, description, severity, confidence,"
    " owasp_category, cwe_id, url, parameter, method, evidence, request_example,"
    " response_snippet, remediation, references_json, scanner, found_at, tags_json"
)
BASE_DEFINITION = """
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id      TEXT NOT NULL REFERENCES scans(session_id) ON DELETE CASCADE,
    finding_id      TEXT NOT NULL,
    title           TEXT NOT NULL,
    description     TEXT NOT NULL DEFAULT '',
    severity        TEXT NOT NULL DEFAULT 'info',
    confidence      TEXT NOT NULL DEFAULT 'tentative',
    owasp_category  TEXT NOT NULL DEFAULT '',
    cwe_id          TEXT NOT NULL DEFAULT '',
    url             TEXT NOT NULL DEFAULT '',
    parameter       TEXT NOT NULL DEFAULT '',
    method          TEXT NOT NULL DEFAULT 'GET',
    evidence        TEXT NOT NULL DEFAULT '',
    request_example TEXT NOT NULL DEFAULT '',
    response_snippet TEXT NOT NULL DEFAULT '',
    remediation     TEXT NOT NULL DEFAULT '',
    references_json TEXT NOT NULL DEFAULT '[]',
    scanner         TEXT NOT NULL DEFAULT '',
    found_at        TEXT NOT NULL DEFAULT '',
    tags_json       TEXT NOT NULL DEFAULT '[]'"""
NEW_DEFINITION = (
    BASE_DEFINITION
    + """,
    observation_id  TEXT NOT NULL,
    fingerprint     TEXT NOT NULL DEFAULT '',
    vuln_class      TEXT NOT NULL DEFAULT '',
    confidence_score REAL NOT NULL DEFAULT 0.5,
    verification_json TEXT NOT NULL DEFAULT '',
    suppression_json TEXT NOT NULL DEFAULT '',
    UNIQUE(session_id, observation_id)"""
)
OLD_DEFINITION = BASE_DEFINITION + ",\n    UNIQUE(session_id, finding_id)"
FINGERPRINT_INDEX = "CREATE INDEX idx_findings_fingerprint ON findings(fingerprint)"
BASE_INDEXES = (
    "CREATE INDEX idx_findings_session ON findings(session_id)",
    "CREATE INDEX idx_findings_severity ON findings(severity)",
)


def _swap(conn: sqlite3.Connection, indexes: tuple[str, ...]) -> None:
    conn.execute("DROP TABLE findings")
    conn.execute("ALTER TABLE findings_new RENAME TO findings")
    for statement in indexes:
        conn.execute(statement)


def apply(conn: sqlite3.Connection) -> None:
    conn.execute(f"CREATE TABLE findings_new ({NEW_DEFINITION})")  # nosec B608
    conn.execute(
        f"INSERT INTO findings_new ({OLD_COLUMNS}, observation_id)"  # nosec B608
        f" SELECT {OLD_COLUMNS}, finding_id FROM findings ORDER BY id"
    )
    _swap(conn, (*BASE_INDEXES, FINGERPRINT_INDEX))


def rollback(conn: sqlite3.Connection) -> None:
    conn.execute(f"CREATE TABLE findings_new ({OLD_DEFINITION})")  # nosec B608
    conn.execute(
        f"INSERT OR IGNORE INTO findings_new ({OLD_COLUMNS})"  # nosec B608
        f" SELECT {OLD_COLUMNS} FROM findings ORDER BY id"
    )
    _swap(conn, BASE_INDEXES)


step(apply, rollback)
