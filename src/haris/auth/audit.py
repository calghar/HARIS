import json
from typing import Any

from .database import SqliteService, now_iso
from .models import AuditEvent


class AuditLog(SqliteService):
    def log_audit(self, event: AuditEvent) -> None:
        if not event.occurred_at:
            event = event.model_copy(update={"occurred_at": now_iso()})
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO audit_log
                    (user_id, user_email, action, resource_id, resource_type,
                     details_json, ip_address, occurred_at)
                VALUES (?,?,?,?,?,?,?,?)
                """,
                (
                    event.user_id,
                    event.user_email,
                    event.action.value,
                    event.resource_id,
                    event.resource_type,
                    json.dumps(event.details),
                    event.ip_address,
                    event.occurred_at,
                ),
            )

    def get_audit_log(
        self,
        limit: int = 100,
        *,
        user_id: str | None = None,
        action: str | None = None,
    ) -> list[dict[str, Any]]:
        conditions: list[str] = []
        params: list[Any] = []
        if user_id:
            conditions.append("user_id = ?")
            params.append(user_id)
        if action:
            conditions.append("action = ?")
            params.append(action)
        where = ("WHERE " + " AND ".join(conditions)) if conditions else ""
        params.append(limit)
        with self._connect() as conn:
            rows = conn.execute(
                f"SELECT * FROM audit_log {where} ORDER BY occurred_at DESC LIMIT ?",  # nosec B608
                params,
            ).fetchall()
        return [dict(r) for r in rows]
