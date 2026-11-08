from pathlib import Path

from ..db.connection import connect
from ..db.migrate import migrate

SCAN = "scan"
TEMPLATE = "template"

_SCHEMA = """CREATE TABLE IF NOT EXISTS resource_owners (
    resource_type TEXT NOT NULL,
    resource_id TEXT NOT NULL,
    owner_user_id TEXT NOT NULL,
    PRIMARY KEY (resource_type, resource_id)
)"""


class ResourceOwners:
    """Owner per scan/template, kept beside the scan data until the scans table
    carries `owner_user_id`; swap this class, not its callers."""

    def __init__(self, db_path: Path) -> None:
        self._db_path = db_path
        migrate(db_path)
        with connect(db_path) as conn:
            conn.execute(_SCHEMA)

    def assign(self, kind: str, resource_id: str, owner_user_id: str) -> None:
        with connect(self._db_path) as conn:
            conn.execute(
                "INSERT OR REPLACE INTO resource_owners VALUES (?,?,?)",
                (kind, resource_id, owner_user_id),
            )

    def owner_of(self, kind: str, resource_id: str) -> str | None:
        with connect(self._db_path) as conn:
            row = conn.execute(
                "SELECT owner_user_id FROM resource_owners"
                " WHERE resource_type = ? AND resource_id = ?",
                (kind, resource_id),
            ).fetchone()
        return str(row["owner_user_id"]) if row else None

    def remove(self, kind: str, resource_id: str) -> None:
        with connect(self._db_path) as conn:
            conn.execute(
                "DELETE FROM resource_owners"
                " WHERE resource_type = ? AND resource_id = ?",
                (kind, resource_id),
            )

    def owned_by(self, kind: str, owner_user_id: str) -> set[str]:
        with connect(self._db_path) as conn:
            rows = conn.execute(
                "SELECT resource_id FROM resource_owners"
                " WHERE resource_type = ? AND owner_user_id = ?",
                (kind, owner_user_id),
            ).fetchall()
        return {str(r["resource_id"]) for r in rows}

    def all_owned(self, kind: str) -> set[str]:
        """Ids of every resource of this kind that has an owner."""
        with connect(self._db_path) as conn:
            rows = conn.execute(
                "SELECT resource_id FROM resource_owners WHERE resource_type = ?",
                (kind,),
            ).fetchall()
        return {str(r["resource_id"]) for r in rows}
