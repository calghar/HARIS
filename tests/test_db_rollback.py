import sqlite3
from contextlib import closing
from pathlib import Path

from yoyo import get_backend, read_migrations

from haris.db.baseline import schema_shape
from haris.db.migrate import MIGRATIONS_DIR, migrate

NEW_STEPS = [
    "0003_finding_identity",
    "0004_scan_owner_state",
    "0005_api_tokens",
    "0006_authorized_targets",
    "0007_job_queue",
    "0008_agent_fields",
]


def _shape(path: Path) -> dict[str, list[tuple[object, ...]]]:
    with closing(sqlite3.connect(path)) as conn:
        return schema_shape(conn)


def test_each_new_step_rolls_back_to_the_schema_before_it(tmp_path: Path) -> None:
    db = tmp_path / "rb.db"
    migrations = {m.id: m for m in read_migrations(str(MIGRATIONS_DIR))}
    backend = get_backend(f"sqlite:///{db.resolve()}")
    before: dict[str, dict[str, list[tuple[object, ...]]]] = {}
    for step_id in ["0001_baseline", "0002_hash_tokens", *NEW_STEPS]:
        before[step_id] = _shape(db) if db.exists() else {}
        backend.apply_one(migrations[step_id])
    backend.connection.close()

    backend = get_backend(f"sqlite:///{db.resolve()}")
    for step_id in reversed(NEW_STEPS):
        backend.rollback_one(migrations[step_id])
        assert _shape(db) == before[step_id], step_id
    backend.connection.close()


def test_findings_rollback_restores_the_unique_finding_id(tmp_path: Path) -> None:
    db = tmp_path / "rb.db"
    migrate(db)
    migrations = {m.id: m for m in read_migrations(str(MIGRATIONS_DIR))}
    with closing(sqlite3.connect(db)) as conn:
        conn.execute("INSERT INTO scans (session_id, target_url) VALUES ('s', 'u')")
        conn.executemany(
            "INSERT INTO findings (session_id, finding_id, title, observation_id)"
            " VALUES ('s', 'same', 't', ?)",
            [("o1",), ("o2",)],
        )
        conn.commit()
    backend = get_backend(f"sqlite:///{db.resolve()}")
    for step_id in reversed(NEW_STEPS):
        backend.rollback_one(migrations[step_id])
    backend.connection.close()

    with closing(sqlite3.connect(db)) as conn:
        assert conn.execute("SELECT COUNT(*) FROM findings").fetchone()[0] == 1
        conn.execute("PRAGMA foreign_keys=ON")
        try:
            conn.execute(
                "INSERT INTO findings (session_id, finding_id, title)"
                " VALUES ('s', 'same', 't')"
            )
        except sqlite3.IntegrityError:
            return
    raise AssertionError("UNIQUE(session_id, finding_id) was not restored")
