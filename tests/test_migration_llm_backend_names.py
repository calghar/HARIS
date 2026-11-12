import sqlite3
from contextlib import closing
from pathlib import Path

import pytest
from yoyo import get_backend, read_migrations

from haris.db.migrate import MIGRATIONS_DIR, migrate

TARGET = "0009_llm_backend_names"
KEPT_TABLES = ("scans", "findings", "llm_enrichments", "scanner_results", "users")


def _backend(db: Path):
    return get_backend(f"sqlite:///{db.resolve()}")


def _db_at_previous_step(db: Path) -> None:
    backend = _backend(db)
    for migration in read_migrations(str(MIGRATIONS_DIR)):
        if migration.id < TARGET:
            backend.apply_one(migration)
    backend.connection.close()


def _apply_target(db: Path) -> None:
    migration = next(m for m in read_migrations(str(MIGRATIONS_DIR)) if m.id == TARGET)
    backend = _backend(db)
    backend.apply_one(migration)
    backend.connection.close()


def _backends(db: Path) -> dict[str, str]:
    with closing(sqlite3.connect(db)) as conn:
        return dict(
            conn.execute("SELECT template_id, llm_backend FROM scan_config_templates")
        )


def _insert_templates(db: Path, backends: dict[str, str]) -> None:
    with closing(sqlite3.connect(db)) as conn:
        conn.executemany(
            "INSERT INTO scan_config_templates (template_id, name, llm_backend)"
            " VALUES (?, ?, ?)",
            [(tid, tid, backend) for tid, backend in backends.items()],
        )
        conn.commit()


def _snapshot(db: Path, tables: tuple[str, ...]) -> dict[str, list[tuple[object, ...]]]:
    with closing(sqlite3.connect(db)) as conn:
        return {
            table: conn.execute(f"SELECT * FROM {table} ORDER BY 1").fetchall()  # nosec B608
            for table in tables
        }


@pytest.mark.parametrize(
    ("before", "after"),
    [
        ("anthropic", "litellm"),
        ("openai", "litellm"),
        ("ollama", "litellm"),
        ("bedrock", "litellm"),
        ("", ""),
        ("litellm", "litellm"),
    ],
)
def test_template_backend_rewritten(tmp_path: Path, before: str, after: str) -> None:
    db = tmp_path / "t.db"
    _db_at_previous_step(db)
    _insert_templates(db, {"tpl": before})

    _apply_target(db)

    assert _backends(db) == {"tpl": after}


def test_applying_twice_changes_nothing_more(tmp_path: Path) -> None:
    db = tmp_path / "t.db"
    _db_at_previous_step(db)
    _insert_templates(
        db, {"a": "anthropic", "b": "bedrock", "c": "", "d": "litellm", "e": "ollama"}
    )
    _apply_target(db)
    first = _snapshot(db, ("scan_config_templates", *KEPT_TABLES))

    migration = next(m for m in read_migrations(str(MIGRATIONS_DIR)) if m.id == TARGET)
    backend = _backend(db)
    backend.rollback_one(migration)
    backend.apply_one(migration)
    backend.connection.close()
    migrate(db)
    migrate(db)

    assert _snapshot(db, ("scan_config_templates", *KEPT_TABLES)) == first
    assert set(_backends(db).values()) == {"litellm", ""}


def test_scans_and_stored_report_untouched(tmp_path: Path) -> None:
    db = tmp_path / "t.db"
    report = tmp_path / "report.md"
    report.write_bytes(b"# Report\nllm_backend: anthropic\n")
    _db_at_previous_step(db)
    _insert_templates(db, {"tpl": "anthropic"})
    with closing(sqlite3.connect(db)) as conn:
        conn.execute(
            "INSERT INTO scans (session_id, target_url, profile_name, template_id)"
            " VALUES ('s1', 'https://example.com', 'quick', 'tpl')"
        )
        conn.execute(
            "INSERT INTO findings (session_id, finding_id, observation_id, title)"
            " VALUES ('s1', 'f1', 'o1', 'Missing HSTS')"
        )
        conn.commit()
    before = _snapshot(db, KEPT_TABLES)
    report_before = report.read_bytes()

    _apply_target(db)

    assert _snapshot(db, KEPT_TABLES) == before
    assert before["scans"], "scan row was not seeded"
    assert report.read_bytes() == report_before
