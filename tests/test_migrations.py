import re
import sqlite3
from pathlib import Path

import pytest

from haris.auth.service import AuthService
from haris.auth.tokens import hash_token
from haris.db.migrate import BACKUP_SUFFIX
from haris.db.store import ScanStore

SCHEMA_0_6_2 = Path(__file__).parent / "fixtures" / "haris_0_6_2_schema.sql"
HEX_64 = re.compile(r"[0-9a-f]{64}")
SESSION_TOKEN = "abc"
REMEMBER_TOKEN = "remember-plain"
VERIFY_TOKEN = "verify-plain"
DATA_TABLES = ("scans", "findings", "scan_config_templates", "users")


def _legacy_db(path: Path) -> None:
    conn = sqlite3.connect(path)
    conn.executescript(SCHEMA_0_6_2.read_text())
    conn.execute("INSERT INTO schema_version (version) VALUES (6)")
    conn.execute(
        "INSERT INTO scans (session_id, target_url, profile_name, started_at,"
        " risk_posture, template_id, started_by)"
        " VALUES ('s1', 'https://example.com', 'quick', '2026-01-01T00:00:00',"
        " 'moderate', 'tpl-1', 'u1')"
    )
    conn.execute(
        "INSERT INTO findings (session_id, finding_id, title, severity, scanner)"
        " VALUES ('s1', 'f1', 'Missing HSTS', 'medium', 'header_checks')"
    )
    conn.execute(
        "INSERT INTO scan_config_templates (template_id, name, is_default)"
        " VALUES ('tpl-1', 'Legacy template', 1)"
    )
    conn.execute(
        "INSERT INTO users (user_id, email, created_at, updated_at)"
        " VALUES ('u1', 'a@example.com', '', '')"
    )
    conn.execute(
        "INSERT INTO user_sessions (token, user_id, expires_at)"
        " VALUES (?, 'u1', '2999-01-01T00:00:00')",
        (SESSION_TOKEN,),
    )
    conn.execute(
        "INSERT INTO remember_tokens (token, user_id, expires_at)"
        " VALUES (?, 'u1', '2999-01-01T00:00:00')",
        (REMEMBER_TOKEN,),
    )
    conn.execute(
        "INSERT INTO email_verifications (token, user_id, expires_at)"
        " VALUES (?, 'u1', '2999-01-01T00:00:00')",
        (VERIFY_TOKEN,),
    )
    conn.commit()
    conn.close()


def _rows(path: Path, table: str) -> list[tuple[object, ...]]:
    with sqlite3.connect(path) as conn:
        return conn.execute(f"SELECT * FROM {table} ORDER BY 1").fetchall()  # nosec B608


def _schema(path: Path) -> list[tuple[str, str, str, str | None]]:
    with sqlite3.connect(path) as conn:
        return conn.execute(
            "SELECT type, name, tbl_name, sql FROM sqlite_master"
            " WHERE name NOT LIKE 'sqlite_%' AND name NOT LIKE '%yoyo%'"
            " ORDER BY type, name"
        ).fetchall()


@pytest.fixture
def upgraded(tmp_path: Path) -> tuple[Path, dict[str, list[tuple[object, ...]]]]:
    db = tmp_path / "legacy.db"
    _legacy_db(db)
    before = {table: _rows(db, table) for table in DATA_TABLES}
    ScanStore(db)
    return db, before


def test_upgrade_keeps_data_and_backs_up(upgraded):
    db, before = upgraded

    for table, rows in before.items():
        width = len(rows[0])
        assert [r[:width] for r in _rows(db, table)] == rows, table
    assert Path(str(db) + BACKUP_SUFFIX).exists()
    session = ScanStore(db).load_session("s1")
    assert session is not None
    assert [f.finding_id for f in session.all_findings] == ["f1"]
    assert session.template_id == "tpl-1"
    assert session.stage_log == []
    assert session.all_findings[0].agent_annotation == ""


def test_upgrade_hashes_every_token_in_place(upgraded):
    db, _ = upgraded
    expected = {
        "user_sessions": SESSION_TOKEN,
        "remember_tokens": REMEMBER_TOKEN,
        "email_verifications": VERIFY_TOKEN,
    }

    for table, plaintext in expected.items():
        (stored,) = _rows(db, table)[0][:1]
        assert HEX_64.fullmatch(stored), table
        assert stored == hash_token(plaintext), table


def test_migrated_cookie_authenticates_and_new_sessions_store_only_hashes(upgraded):
    """Scenario: Migrated session survives."""
    db, _ = upgraded
    auth = AuthService(db)

    migrated = auth.get_session(SESSION_TOKEN)
    created = auth.create_session("u1")

    assert migrated is not None
    assert migrated.token == ""
    assert migrated.token_hash == hash_token(SESSION_TOKEN)
    assert auth.get_session(created.token) is not None
    stored = {row[0] for row in _rows(db, "user_sessions")}
    assert created.token not in stored
    assert created.token_hash in stored
    assert auth.consume_remember_token(REMEMBER_TOKEN) is not None
    assert auth.consume_email_verification_token(VERIFY_TOKEN) is not None


def test_fresh_schema_equals_upgraded_schema(upgraded, tmp_path):
    db, _ = upgraded
    ScanStore(tmp_path / "fresh.db")

    assert _schema(tmp_path / "fresh.db") == _schema(db)


def test_backup_is_taken_once_and_never_for_fresh_files(upgraded, tmp_path):
    db, _ = upgraded
    backup = Path(str(db) + BACKUP_SUFFIX)
    backup_bytes = backup.read_bytes()

    ScanStore(db)
    ScanStore(tmp_path / "fresh.db")

    assert backup.read_bytes() == backup_bytes
    assert not (tmp_path / f"fresh.db{BACKUP_SUFFIX}").exists()
