from typing import Any
from urllib.parse import urlparse

from ..auth.models import User
from .access import visible_scan_ids
from .state import AppState

SEVERITIES = ("critical", "high", "medium", "low", "info")
RECENT_WEBSITES = 5
RECENT_FINDINGS = 10


def _host(url: str) -> str:
    return urlparse(url).hostname or "unknown"


def _visible_rows(state: AppState, user: User) -> list[dict[str, Any]] | None:
    """Summary rows (newest first) the user may see, or None for no restriction."""
    allowed = visible_scan_ids(state, user)
    if allowed is None:
        return None
    return [r for r in state.store.list_sessions() if r["session_id"] in allowed]


def list_scans(
    state: AppState, user: User, *, page: int, per_page: int, **filters: str | None
) -> tuple[list[dict[str, Any]], int]:
    allowed = visible_scan_ids(state, user)
    if allowed is None:
        return state.store.list_sessions_paginated(
            page=page, per_page=per_page, **filters
        )
    _, total = state.store.list_sessions_paginated(page=1, per_page=1, **filters)
    rows, _ = state.store.list_sessions_paginated(
        page=1, per_page=max(total, 1), **filters
    )
    mine = [r for r in rows if r["session_id"] in allowed]
    start = (page - 1) * per_page
    return mine[start : start + per_page], len(mine)


def list_websites(state: AppState, user: User) -> list[dict[str, Any]]:
    rows = _visible_rows(state, user)
    if rows is None:
        return state.store.list_websites()
    websites: dict[str, dict[str, Any]] = {}
    for row in rows:
        entry = websites.setdefault(
            _host(row["target_url"]),
            {
                "hostname": _host(row["target_url"]),
                "scan_count": 0,
                "last_scanned": row["started_at"],
                "first_scanned": row["started_at"],
                "latest_risk_posture": row["risk_posture"],
                "latest_finding_count": row["finding_count"],
            },
        )
        entry["scan_count"] += 1
        entry["first_scanned"] = min(entry["first_scanned"], row["started_at"])
    return list(websites.values())


def scans_for_hostname(
    state: AppState, user: User, hostname: str
) -> list[dict[str, Any]]:
    scans = state.store.get_scans_for_hostname(hostname)
    allowed = visible_scan_ids(state, user)
    if allowed is None:
        return scans
    return [s for s in scans if s["session_id"] in allowed]


def severity_trends(state: AppState, user: User, hostname: str) -> dict[str, Any]:
    if visible_scan_ids(state, user) is None:
        return state.store.get_severity_trends(hostname)
    scans = sorted(
        scans_for_hostname(state, user, hostname), key=lambda s: s["started_at"]
    )
    counts: list[dict[str, int]] = []
    for scan in scans:
        by_severity = dict.fromkeys(SEVERITIES, 0)
        for finding in state.store.get_findings(scan["session_id"]):
            by_severity[finding["severity"]] += 1
        counts.append(by_severity)
    return {
        "labels": [s["started_at"][:10] for s in scans],
        "datasets": {sev: [c[sev] for c in counts] for sev in SEVERITIES},
        "latest_severity": counts[-1] if counts else dict.fromkeys(SEVERITIES, 0),
    }


def dashboard_summary(state: AppState, user: User) -> dict[str, Any]:
    rows = _visible_rows(state, user)
    if rows is None:
        return state.store.dashboard_summary()
    recent_findings: list[dict[str, Any]] = []
    for row in rows:
        for finding in state.store.get_findings(row["session_id"]):
            if finding["severity"] in ("critical", "high"):
                recent_findings.append(
                    {
                        "finding_id": finding["finding_id"],
                        "title": finding["title"],
                        "severity": finding["severity"],
                        "url": finding["url"],
                        "session_id": row["session_id"],
                        "target_url": row["target_url"],
                    }
                )
        if len(recent_findings) >= RECENT_FINDINGS:
            break
    recent_findings = recent_findings[:RECENT_FINDINGS]
    recent_websites = [
        {
            "hostname": w["hostname"],
            "risk_posture": w["latest_risk_posture"],
            "finding_count": w["latest_finding_count"],
            "last_scanned": w["last_scanned"],
        }
        for w in list_websites(state, user)[:RECENT_WEBSITES]
    ]
    return {
        "total_websites": len({_host(r["target_url"]) for r in rows}),
        "total_scans": len(rows),
        "open_critical_high": len(recent_findings),
        "latest_scan_time": rows[0]["started_at"] if rows else "",
        "recent_findings": recent_findings,
        "recent_websites": recent_websites,
    }
