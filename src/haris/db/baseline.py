import sqlite3

SCHEMA_VERSION = 6

_TABLES_SQL = """\
CREATE TABLE IF NOT EXISTS schema_version (
    version INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS scans (
    session_id   TEXT PRIMARY KEY,
    target_url   TEXT NOT NULL,
    profile_name TEXT NOT NULL DEFAULT '',
    profile_intro TEXT NOT NULL DEFAULT '',
    started_at   TEXT NOT NULL DEFAULT '',
    finished_at  TEXT NOT NULL DEFAULT '',
    scanners_used TEXT NOT NULL DEFAULT '[]',
    risk_posture TEXT NOT NULL DEFAULT 'excellent',
    risk_posture_text TEXT NOT NULL DEFAULT '',
    errors       TEXT NOT NULL DEFAULT '[]',
    target_json  TEXT NOT NULL DEFAULT '{}'
);

CREATE TABLE IF NOT EXISTS findings (
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
    tags_json       TEXT NOT NULL DEFAULT '[]',
    UNIQUE(session_id, finding_id)
);

CREATE TABLE IF NOT EXISTS remediation_steps (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id    TEXT NOT NULL REFERENCES scans(session_id) ON DELETE CASCADE,
    title         TEXT NOT NULL,
    description   TEXT NOT NULL DEFAULT '',
    effort        TEXT NOT NULL DEFAULT 'moderate',
    impact        TEXT NOT NULL DEFAULT 'medium',
    finding_count INTEGER NOT NULL DEFAULT 0,
    category      TEXT NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_findings_session ON findings(session_id);
CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);
CREATE INDEX IF NOT EXISTS idx_remediation_session ON remediation_steps(session_id);

CREATE TABLE IF NOT EXISTS llm_enrichments (
    id                      INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id              TEXT NOT NULL
        REFERENCES scans(session_id) ON DELETE CASCADE,
    finding_id              TEXT NOT NULL,
    attack_narrative        TEXT NOT NULL DEFAULT '',
    business_impact_assessment TEXT NOT NULL DEFAULT '',
    exploitation_complexity TEXT NOT NULL DEFAULT '',
    false_positive_likelihood TEXT NOT NULL DEFAULT '',
    related_cwes            TEXT NOT NULL DEFAULT '[]',
    attack_chain_position   TEXT NOT NULL DEFAULT '',
    variant_suggestions     TEXT NOT NULL DEFAULT '[]',
    UNIQUE(session_id, finding_id)
);

CREATE TABLE IF NOT EXISTS attack_chains (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id      TEXT NOT NULL REFERENCES scans(session_id) ON DELETE CASCADE,
    chain_id        TEXT NOT NULL,
    name            TEXT NOT NULL,
    description     TEXT NOT NULL DEFAULT '',
    finding_ids     TEXT NOT NULL DEFAULT '[]',
    total_impact    TEXT NOT NULL DEFAULT '',
    likelihood      TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS triaged_findings (
    id                   INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id           TEXT NOT NULL REFERENCES scans(session_id) ON DELETE CASCADE,
    finding_id           TEXT NOT NULL,
    original_severity    TEXT NOT NULL DEFAULT 'info',
    adjusted_severity    TEXT NOT NULL DEFAULT 'info',
    exploitability_score INTEGER NOT NULL DEFAULT 5,
    business_priority    INTEGER NOT NULL DEFAULT 5,
    triage_rationale     TEXT NOT NULL DEFAULT '',
    recommended_timeline TEXT NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_llm_enrichments_session ON llm_enrichments(session_id);
CREATE INDEX IF NOT EXISTS idx_attack_chains_session ON attack_chains(session_id);
CREATE INDEX IF NOT EXISTS idx_triaged_findings_session ON triaged_findings(session_id);

CREATE TABLE IF NOT EXISTS scan_config_templates (
    template_id    TEXT PRIMARY KEY,
    name           TEXT NOT NULL,
    description    TEXT NOT NULL DEFAULT '',
    profile        TEXT NOT NULL DEFAULT 'quick',
    rate_limit_rps REAL NOT NULL DEFAULT 10.0,
    max_requests   INTEGER NOT NULL DEFAULT 10000,
    excluded_paths TEXT NOT NULL DEFAULT '[]',
    auth_method    TEXT NOT NULL DEFAULT 'none',
    report_formats TEXT NOT NULL DEFAULT '["markdown","json"]',
    llm_enrichment INTEGER NOT NULL DEFAULT 0,
    llm_backend    TEXT NOT NULL DEFAULT '',
    scanner_options TEXT NOT NULL DEFAULT '{}',
    tags           TEXT NOT NULL DEFAULT '[]',
    is_default     INTEGER NOT NULL DEFAULT 0,
    created_at     TEXT NOT NULL DEFAULT '',
    updated_at     TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_sct_name ON scan_config_templates(name);

CREATE TABLE IF NOT EXISTS scanner_results (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id    TEXT NOT NULL REFERENCES scans(session_id) ON DELETE CASCADE,
    scanner_name  TEXT NOT NULL,
    errors_json   TEXT NOT NULL DEFAULT '[]',
    metadata_json TEXT NOT NULL DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS idx_scanner_results_session ON scanner_results(session_id);

CREATE TABLE IF NOT EXISTS users (
    user_id       TEXT PRIMARY KEY,
    email         TEXT NOT NULL UNIQUE,
    display_name  TEXT NOT NULL DEFAULT '',
    password_hash TEXT NOT NULL DEFAULT '',
    role          TEXT NOT NULL DEFAULT 'user',
    auth_provider TEXT NOT NULL DEFAULT 'local',
    oidc_sub      TEXT NOT NULL DEFAULT '',
    is_active     INTEGER NOT NULL DEFAULT 1,
    created_at    TEXT NOT NULL DEFAULT '',
    updated_at    TEXT NOT NULL DEFAULT '',
    last_login_at TEXT NOT NULL DEFAULT ''
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_users_email ON users(email);
CREATE INDEX IF NOT EXISTS idx_users_oidc_sub ON users(oidc_sub) WHERE oidc_sub != '';

CREATE TABLE IF NOT EXISTS user_sessions (
    token        TEXT PRIMARY KEY,
    user_id      TEXT NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
    created_at   TEXT NOT NULL DEFAULT '',
    expires_at   TEXT NOT NULL DEFAULT '',
    last_seen_at TEXT NOT NULL DEFAULT '',
    ip_address   TEXT NOT NULL DEFAULT '',
    user_agent   TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_sessions_user    ON user_sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_sessions_expires ON user_sessions(expires_at);

CREATE TABLE IF NOT EXISTS remember_tokens (
    token      TEXT PRIMARY KEY,
    user_id    TEXT NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
    created_at TEXT NOT NULL DEFAULT '',
    expires_at TEXT NOT NULL DEFAULT '',
    used_at    TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_remember_user ON remember_tokens(user_id);

CREATE TABLE IF NOT EXISTS audit_log (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id       TEXT NOT NULL DEFAULT '',
    user_email    TEXT NOT NULL DEFAULT '',
    action        TEXT NOT NULL DEFAULT '',
    resource_id   TEXT NOT NULL DEFAULT '',
    resource_type TEXT NOT NULL DEFAULT '',
    details_json  TEXT NOT NULL DEFAULT '{}',
    ip_address    TEXT NOT NULL DEFAULT '',
    occurred_at   TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_audit_user     ON audit_log(user_id);
CREATE INDEX IF NOT EXISTS idx_audit_action   ON audit_log(action);
CREATE INDEX IF NOT EXISTS idx_audit_occurred ON audit_log(occurred_at);

CREATE TABLE IF NOT EXISTS email_verifications (
    token      TEXT PRIMARY KEY,
    user_id    TEXT NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
    purpose    TEXT NOT NULL DEFAULT 'registration',
    created_at TEXT NOT NULL DEFAULT '',
    expires_at TEXT NOT NULL DEFAULT '',
    used_at    TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_email_verif_user    ON email_verifications(user_id);
CREATE INDEX IF NOT EXISTS idx_email_verif_expires ON email_verifications(expires_at);
"""

_SCANS_ADDED_COLUMNS = (
    ("false_positive_assessments", "TEXT NOT NULL DEFAULT '[]'"),
    ("executive_priorities", "TEXT NOT NULL DEFAULT ''"),
    ("template_id", "TEXT NOT NULL DEFAULT ''"),
    ("started_by", "TEXT NOT NULL DEFAULT ''"),
)

_SCANS_INDEX_SQL = "CREATE INDEX IF NOT EXISTS idx_scans_template ON scans(template_id)"


def _statements(sql: str) -> list[str]:
    return [s for s in sql.split(";") if s.strip()]


def apply_baseline(conn: sqlite3.Connection) -> None:
    for statement in _statements(_TABLES_SQL):
        conn.execute(statement)
    present = {row[1] for row in conn.execute("PRAGMA table_info(scans)")}
    for name, definition in _SCANS_ADDED_COLUMNS:
        if name not in present:
            conn.execute(f"ALTER TABLE scans ADD COLUMN {name} {definition}")
    conn.execute(_SCANS_INDEX_SQL)
    conn.execute("DELETE FROM schema_version")
    conn.execute("INSERT INTO schema_version (version) VALUES (?)", (SCHEMA_VERSION,))


def schema_shape(conn: sqlite3.Connection) -> dict[str, list[tuple[object, ...]]]:
    names = [
        row[0]
        for row in conn.execute(
            "SELECT name FROM sqlite_master WHERE type IN ('table', 'index')"
            " AND name NOT LIKE 'sqlite_%' AND name NOT LIKE '%yoyo%'"
            " ORDER BY name"
        )
    ]
    return {
        name: [tuple(row) for row in conn.execute(f"PRAGMA table_xinfo({name})")]
        for name in names
    }
