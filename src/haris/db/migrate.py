import logging
import sqlite3
from contextlib import closing
from pathlib import Path

from yoyo import get_backend, read_migrations

from .baseline import SCHEMA_VERSION, apply_baseline, schema_shape

logger = logging.getLogger(__name__)

MIGRATIONS_DIR = Path(__file__).parent / "migrations"
BASELINE_ID = "0001_baseline"
BACKUP_SUFFIX = ".pre-0.7.bak"
YOYO_TABLE = "_yoyo_migration"


def _is_pre_yoyo(path: Path) -> bool:
    if not path.exists():
        return False
    with closing(sqlite3.connect(path)) as conn:
        tables = {
            row[0]
            for row in conn.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table'"
                " AND name NOT LIKE 'sqlite_%'"
            )
        }
    return bool(tables) and YOYO_TABLE not in tables


def _backup(path: Path) -> None:
    target = path.with_name(path.name + BACKUP_SUFFIX)
    if target.exists():
        return
    with closing(sqlite3.connect(path)) as src, closing(sqlite3.connect(target)) as dst:
        src.backup(dst)
    logger.info("Backed up %s to %s before migrating", path, target)


def _matches_baseline(path: Path) -> bool:
    with closing(sqlite3.connect(path)) as conn:
        try:
            version = conn.execute("SELECT version FROM schema_version").fetchone()
        except sqlite3.OperationalError:
            return False
        if version is None or version[0] != SCHEMA_VERSION:
            return False
        actual = schema_shape(conn)
    with closing(sqlite3.connect(":memory:")) as reference:
        apply_baseline(reference)
        return actual == schema_shape(reference)


def migrate(db_path: str | Path) -> None:
    path = Path(db_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    pre_yoyo = _is_pre_yoyo(path)
    if pre_yoyo:
        _backup(path)
    adopt_baseline = pre_yoyo and _matches_baseline(path)
    with closing(sqlite3.connect(path)) as conn:
        conn.execute("PRAGMA journal_mode=WAL")
    migrations = read_migrations(str(MIGRATIONS_DIR))
    backend = get_backend(f"sqlite:///{path.resolve()}")
    with backend.lock():
        if adopt_baseline:
            backend.mark_migrations([m for m in migrations if m.id == BASELINE_ID])
        backend.apply_migrations(backend.to_apply(migrations))
    backend.connection.close()
