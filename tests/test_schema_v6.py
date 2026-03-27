import sqlite3

import pytest

from src.db.store import _SCHEMA_VERSION, ScanStore


def test_schema_version_is_6():
    assert _SCHEMA_VERSION == 6


def test_v6_fresh_install_creates_auth_tables(tmp_path):
    """A fresh ScanStore should have all V6 auth tables."""
    store = ScanStore(db_path=tmp_path / "test.db")
    with store._connect() as conn:
        tables = {
            r[0]
            for r in conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            ).fetchall()
        }

    assert "users" in tables
    assert "user_sessions" in tables
    assert "remember_tokens" in tables
    assert "audit_log" in tables
    assert "email_verifications" in tables


def test_v6_scans_has_started_by_column(tmp_path):
    """The scans table should carry the started_by column added in V6."""
    ScanStore(db_path=tmp_path / "test.db")
    conn = sqlite3.connect(str(tmp_path / "test.db"))
    cols = {r[1] for r in conn.execute("PRAGMA table_info(scans)").fetchall()}
    conn.close()
    assert "started_by" in cols


def test_users_table_has_expected_columns(tmp_path):
    ScanStore(db_path=tmp_path / "test.db")
    conn = sqlite3.connect(str(tmp_path / "test.db"))
    cols = {r[1] for r in conn.execute("PRAGMA table_info(users)").fetchall()}
    conn.close()
    expected = {
        "user_id",
        "email",
        "display_name",
        "password_hash",
        "role",
        "auth_provider",
        "oidc_sub",
        "is_active",
        "created_at",
        "updated_at",
        "last_login_at",
    }
    assert expected.issubset(cols)


def test_user_sessions_table_has_expected_columns(tmp_path):
    ScanStore(db_path=tmp_path / "test.db")
    conn = sqlite3.connect(str(tmp_path / "test.db"))
    cols = {r[1] for r in conn.execute("PRAGMA table_info(user_sessions)").fetchall()}
    conn.close()
    expected = {
        "token",
        "user_id",
        "created_at",
        "expires_at",
        "last_seen_at",
        "ip_address",
        "user_agent",
    }
    assert expected.issubset(cols)


def test_audit_log_table_has_expected_columns(tmp_path):
    ScanStore(db_path=tmp_path / "test.db")
    conn = sqlite3.connect(str(tmp_path / "test.db"))
    cols = {r[1] for r in conn.execute("PRAGMA table_info(audit_log)").fetchall()}
    conn.close()
    expected = {
        "id",
        "user_id",
        "user_email",
        "action",
        "resource_id",
        "resource_type",
        "details_json",
        "ip_address",
        "occurred_at",
    }
    assert expected.issubset(cols)


def test_email_verifications_table_has_expected_columns(tmp_path):
    ScanStore(db_path=tmp_path / "test.db")
    conn = sqlite3.connect(str(tmp_path / "test.db"))
    cols = {
        r[1] for r in conn.execute("PRAGMA table_info(email_verifications)").fetchall()
    }
    conn.close()
    expected = {"token", "user_id", "purpose", "created_at", "expires_at", "used_at"}
    assert expected.issubset(cols)


def test_users_table_unique_email_constraint(tmp_path):
    ScanStore(db_path=tmp_path / "test.db")
    conn = sqlite3.connect(str(tmp_path / "test.db"))
    conn.execute(
        "INSERT INTO users (user_id, email, created_at, updated_at)"
        " VALUES ('a', 'x@y.com', '', '')"
    )
    conn.commit()
    with pytest.raises(sqlite3.IntegrityError):
        conn.execute(
            "INSERT INTO users (user_id, email, created_at, updated_at)"
            " VALUES ('b', 'x@y.com', '', '')"
        )
    conn.close()


def test_sessions_cascade_delete_on_user_delete(tmp_path):
    ScanStore(db_path=tmp_path / "test.db")
    conn = sqlite3.connect(str(tmp_path / "test.db"))
    conn.execute("PRAGMA foreign_keys=ON")
    conn.execute(
        "INSERT INTO users (user_id, email, created_at, updated_at)"
        " VALUES ('u1', 'a@b.com', '', '')"
    )
    conn.execute(
        "INSERT INTO user_sessions"
        " (token, user_id, created_at, expires_at, last_seen_at)"
        " VALUES ('tok1', 'u1', '', '2099-01-01', '')"
    )
    conn.commit()
    conn.execute("DELETE FROM users WHERE user_id = 'u1'")
    conn.commit()
    row = conn.execute("SELECT * FROM user_sessions WHERE token = 'tok1'").fetchone()
    conn.close()
    assert row is None


def test_remember_tokens_cascade_delete_on_user_delete(tmp_path):
    ScanStore(db_path=tmp_path / "test.db")
    conn = sqlite3.connect(str(tmp_path / "test.db"))
    conn.execute("PRAGMA foreign_keys=ON")
    conn.execute(
        "INSERT INTO users (user_id, email, created_at, updated_at)"
        " VALUES ('u2', 'c@d.com', '', '')"
    )
    conn.execute(
        "INSERT INTO remember_tokens (token, user_id, created_at, expires_at, used_at)"
        " VALUES ('remtok1', 'u2', '', '2099-01-01', '')"
    )
    conn.commit()
    conn.execute("DELETE FROM users WHERE user_id = 'u2'")
    conn.commit()
    row = conn.execute(
        "SELECT * FROM remember_tokens WHERE token = 'remtok1'"
    ).fetchone()
    conn.close()
    assert row is None


def test_email_verifications_cascade_delete_on_user_delete(tmp_path):
    ScanStore(db_path=tmp_path / "test.db")
    conn = sqlite3.connect(str(tmp_path / "test.db"))
    conn.execute("PRAGMA foreign_keys=ON")
    conn.execute(
        "INSERT INTO users (user_id, email, created_at, updated_at)"
        " VALUES ('u3', 'e@f.com', '', '')"
    )
    conn.execute(
        "INSERT INTO email_verifications"
        " (token, user_id, purpose, created_at, expires_at, used_at)"
        " VALUES ('evtok1', 'u3', 'registration', '', '2099-01-01', '')"
    )
    conn.commit()
    conn.execute("DELETE FROM users WHERE user_id = 'u3'")
    conn.commit()
    row = conn.execute(
        "SELECT * FROM email_verifications WHERE token = 'evtok1'"
    ).fetchone()
    conn.close()
    assert row is None


def test_audit_log_insert_and_query(tmp_path):
    ScanStore(db_path=tmp_path / "test.db")
    conn = sqlite3.connect(str(tmp_path / "test.db"))
    conn.execute(
        "INSERT INTO audit_log"
        " (user_id, user_email, action, resource_id, resource_type,"
        "  details_json, ip_address, occurred_at)"
        " VALUES ('u1', 'a@b.com', 'scan.started', 's1', 'scan',"
        "  '{}', '127.0.0.1', '2026-01-01T00:00:00')"
    )
    conn.commit()
    row = conn.execute("SELECT * FROM audit_log WHERE resource_id = 's1'").fetchone()
    conn.close()
    assert row is not None
    # columns: id, user_id, user_email, action, ...
    assert row[3] == "scan.started"


def test_schema_version_recorded_in_db(tmp_path):
    store = ScanStore(db_path=tmp_path / "test.db")
    with store._connect() as conn:
        version = conn.execute("SELECT version FROM schema_version LIMIT 1").fetchone()[
            "version"
        ]
    assert version == 6


def test_second_store_init_does_not_corrupt_schema(tmp_path):
    """Initialising a second ScanStore against the same DB must leave V6 intact."""
    ScanStore(db_path=tmp_path / "shared.db")
    store2 = ScanStore(db_path=tmp_path / "shared.db")
    with store2._connect() as conn:
        version = conn.execute("SELECT version FROM schema_version LIMIT 1").fetchone()[
            "version"
        ]
    assert version == 6
