import json
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from .connection import connect

_SEVERITIES = ("critical", "high", "medium", "low", "info")
_RECENT_WEBSITES = 5
_FINISHED = "s.scan_state NOT IN ('pending', 'running')"


def _hostname(url: str) -> str:
    return urlparse(url).hostname or "unknown"


def _owned(owner_user_id: str | None, *clauses: str) -> tuple[str, list[str]]:
    """WHERE clause for the owner filter plus *clauses*; None means every owner."""
    parts = list(clauses)
    params: list[str] = []
    if owner_user_id is not None:
        parts.append("s.owner_user_id = ?")
        params.append(owner_user_id)
    return (" WHERE " + " AND ".join(parts) if parts else ""), params


class WebsiteRepository:
    def __init__(self, db_path: Path) -> None:
        self._db_path = db_path

    def _finished_rows(self, owner_user_id: str | None) -> list[Any]:
        where, params = _owned(owner_user_id, _FINISHED)
        with connect(self._db_path) as conn:
            return conn.execute(
                f"""SELECT s.session_id, s.target_url, s.started_at, s.risk_posture,
                           s.profile_name, s.template_id, s.scanners_used,
                           COUNT(f.id) AS finding_count
                    FROM scans s
                    LEFT JOIN findings f ON f.session_id = s.session_id
                    {where}
                    GROUP BY s.session_id
                    ORDER BY s.started_at DESC""",  # nosec B608
                params,
            ).fetchall()

    def dashboard_summary(self, owner_user_id: str | None = None) -> dict[str, Any]:
        where, params = _owned(owner_user_id)
        severe_where, severe_params = _owned(
            owner_user_id, "f.severity IN ('critical', 'high')"
        )
        with connect(self._db_path) as conn:
            total_scans = conn.execute(
                f"SELECT COUNT(*) AS c FROM scans s{where}",  # nosec B608
                params,
            ).fetchone()["c"]
            urls = conn.execute(
                f"SELECT DISTINCT s.target_url FROM scans s{where}",  # nosec B608
                params,
            ).fetchall()
            critical_findings = conn.execute(
                f"""SELECT f.finding_id, f.title, f.severity, f.url,
                           s.session_id, s.target_url
                    FROM findings f
                    JOIN scans s ON s.session_id = f.session_id
                    {severe_where}
                    ORDER BY s.started_at DESC
                    LIMIT 10""",  # nosec B608
                severe_params,
            ).fetchall()
            latest = conn.execute(
                f"SELECT s.started_at FROM scans s{where}"  # nosec B608
                " ORDER BY s.started_at DESC LIMIT 1",
                params,
            ).fetchone()
        session_rows = self._finished_rows(owner_user_id)

        recent_findings = [
            {
                key: r[key]
                for key in (
                    "finding_id",
                    "title",
                    "severity",
                    "url",
                    "session_id",
                    "target_url",
                )
            }
            for r in critical_findings
        ]
        seen: set[str] = set()
        recent_websites: list[dict[str, Any]] = []
        for row in session_rows:
            host = _hostname(row["target_url"])
            if host in seen:
                continue
            seen.add(host)
            recent_websites.append(
                {
                    "hostname": host,
                    "risk_posture": row["risk_posture"],
                    "finding_count": row["finding_count"],
                    "last_scanned": row["started_at"],
                }
            )
            if len(recent_websites) >= _RECENT_WEBSITES:
                break

        return {
            "total_websites": len({_hostname(r["target_url"]) for r in urls}),
            "total_scans": total_scans,
            "open_critical_high": len(recent_findings),
            "latest_scan_time": latest["started_at"] if latest else "",
            "recent_findings": recent_findings,
            "recent_websites": recent_websites,
        }

    def list_websites(self, owner_user_id: str | None = None) -> list[dict[str, Any]]:
        websites: dict[str, dict[str, Any]] = {}
        for row in self._finished_rows(owner_user_id):
            host = _hostname(row["target_url"])
            if host not in websites:
                websites[host] = {
                    "hostname": host,
                    "scan_count": 0,
                    "last_scanned": row["started_at"],
                    "first_scanned": row["started_at"],
                    "latest_risk_posture": row["risk_posture"],
                    "latest_finding_count": row["finding_count"],
                }
            websites[host]["scan_count"] += 1
            if row["started_at"] < websites[host]["first_scanned"]:
                websites[host]["first_scanned"] = row["started_at"]
        return list(websites.values())

    def get_scans_for_hostname(
        self, hostname: str, owner_user_id: str | None = None
    ) -> list[dict[str, Any]]:
        return [
            {
                "session_id": row["session_id"],
                "target_url": row["target_url"],
                "profile_name": row["profile_name"],
                "started_at": row["started_at"],
                "risk_posture": row["risk_posture"],
                "finding_count": row["finding_count"],
                "template_id": row["template_id"],
                "scanners_used": json.loads(row["scanners_used"]),
            }
            for row in self._finished_rows(owner_user_id)
            if _hostname(row["target_url"]) == hostname
        ]

    def get_severity_trends(
        self, hostname: str, owner_user_id: str | None = None
    ) -> dict[str, Any]:
        where, params = _owned(owner_user_id, _FINISHED)
        with connect(self._db_path) as conn:
            rows = conn.execute(
                f"""SELECT s.session_id, s.started_at, s.target_url,
                           f.severity, COUNT(f.id) AS count
                    FROM scans s
                    JOIN findings f ON f.session_id = s.session_id
                    {where}
                    GROUP BY s.session_id, f.severity
                    ORDER BY s.started_at ASC""",  # nosec B608
                params,
            ).fetchall()

        scans_order: list[str] = []
        scan_dates: dict[str, str] = {}
        severity_data: dict[str, dict[str, int]] = {}
        for row in rows:
            if _hostname(row["target_url"]) != hostname:
                continue
            sid = row["session_id"]
            if sid not in scan_dates:
                scans_order.append(sid)
                scan_dates[sid] = row["started_at"][:10]
                severity_data[sid] = {}
            severity_data[sid][row["severity"]] = row["count"]

        datasets = {
            sev: [severity_data.get(sid, {}).get(sev, 0) for sid in scans_order]
            for sev in _SEVERITIES
        }
        latest_severity = dict.fromkeys(_SEVERITIES, 0)
        if scans_order:
            latest_severity.update(severity_data.get(scans_order[-1], {}))
        return {
            "labels": [scan_dates[sid] for sid in scans_order],
            "datasets": datasets,
            "latest_severity": latest_severity,
        }
