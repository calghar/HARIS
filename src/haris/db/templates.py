import json
import sqlite3
from pathlib import Path
from typing import Any

from ..models.scan_config_template import ScanConfigTemplate
from .connection import connect
from .template_defaults import default_templates


def _to_template(row: sqlite3.Row) -> ScanConfigTemplate:
    return ScanConfigTemplate(
        template_id=row["template_id"],
        name=row["name"],
        description=row["description"],
        profile=row["profile"],
        rate_limit_rps=row["rate_limit_rps"],
        max_requests=row["max_requests"],
        excluded_paths=json.loads(row["excluded_paths"]),
        auth_method=row["auth_method"],
        report_formats=json.loads(row["report_formats"]),
        llm_enrichment=bool(row["llm_enrichment"]),
        llm_backend=row["llm_backend"],
        scanner_options=json.loads(row["scanner_options"]),
        tags=json.loads(row["tags"]),
        is_default=bool(row["is_default"]),
        created_at=row["created_at"],
        updated_at=row["updated_at"],
    )


class TemplateRepository:
    def __init__(self, db_path: Path) -> None:
        self._db_path = db_path

    def save(self, tpl: ScanConfigTemplate) -> None:
        with connect(self._db_path) as conn:
            conn.execute(
                """INSERT OR REPLACE INTO scan_config_templates
                   (template_id, name, description, profile,
                    rate_limit_rps, max_requests, excluded_paths,
                    auth_method, report_formats, llm_enrichment,
                    llm_backend, scanner_options, tags, is_default,
                    created_at, updated_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    tpl.template_id,
                    tpl.name,
                    tpl.description,
                    tpl.profile,
                    tpl.rate_limit_rps,
                    tpl.max_requests,
                    json.dumps(tpl.excluded_paths),
                    tpl.auth_method,
                    json.dumps(tpl.report_formats),
                    int(tpl.llm_enrichment),
                    tpl.llm_backend,
                    json.dumps(tpl.scanner_options),
                    json.dumps(tpl.tags),
                    int(tpl.is_default),
                    tpl.created_at,
                    tpl.updated_at,
                ),
            )

    def get(self, template_id: str) -> ScanConfigTemplate | None:
        with connect(self._db_path) as conn:
            row = conn.execute(
                "SELECT * FROM scan_config_templates WHERE template_id = ?",
                (template_id,),
            ).fetchone()
        return _to_template(row) if row else None

    def list_all(self) -> list[dict[str, Any]]:
        with connect(self._db_path) as conn:
            rows = conn.execute(
                """SELECT * FROM scan_config_templates
                   ORDER BY is_default DESC, name ASC"""
            ).fetchall()
        return [
            {
                "template_id": row["template_id"],
                "name": row["name"],
                "description": row["description"],
                "profile": row["profile"],
                "rate_limit_rps": row["rate_limit_rps"],
                "max_requests": row["max_requests"],
                "scanner_options": json.loads(row["scanner_options"]),
                "tags": json.loads(row["tags"]),
                "is_default": bool(row["is_default"]),
                "created_at": row["created_at"],
                "updated_at": row["updated_at"],
            }
            for row in rows
        ]

    def delete(self, template_id: str) -> bool:
        with connect(self._db_path) as conn:
            cursor = conn.execute(
                "DELETE FROM scan_config_templates WHERE template_id = ?",
                (template_id,),
            )
            return cursor.rowcount > 0

    def set_default(self, template_id: str) -> None:
        with connect(self._db_path) as conn:
            conn.execute("UPDATE scan_config_templates SET is_default = 0")
            conn.execute(
                "UPDATE scan_config_templates SET is_default = 1 WHERE template_id = ?",
                (template_id,),
            )

    def get_default(self) -> ScanConfigTemplate | None:
        with connect(self._db_path) as conn:
            row = conn.execute(
                "SELECT * FROM scan_config_templates WHERE is_default = 1"
            ).fetchone()
        return _to_template(row) if row else None

    def seed_defaults(self) -> None:
        with connect(self._db_path) as conn:
            count = conn.execute(
                "SELECT COUNT(*) AS c FROM scan_config_templates"
            ).fetchone()["c"]
        if count == 0:
            for tpl in default_templates():
                self.save(tpl)
