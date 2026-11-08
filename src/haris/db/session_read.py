import json
import sqlite3

from ..models import (
    Confidence,
    Effort,
    Finding,
    RemediationStep,
    RiskPosture,
    ScannerResult,
    ScanSession,
    Severity,
    Target,
)
from .llm_data import read_llm_data


def _finding(row: sqlite3.Row) -> Finding:
    return Finding(
        finding_id=row["finding_id"],
        title=row["title"],
        description=row["description"],
        severity=Severity(row["severity"]),
        confidence=Confidence(row["confidence"]),
        owasp_category=row["owasp_category"],
        cwe_id=row["cwe_id"],
        url=row["url"],
        parameter=row["parameter"],
        method=row["method"],
        evidence=row["evidence"],
        request_example=row["request_example"],
        response_snippet=row["response_snippet"],
        remediation=row["remediation"],
        references=json.loads(row["references_json"]),
        scanner=row["scanner"],
        found_at=row["found_at"],
        tags=json.loads(row["tags_json"]),
    )


def _scanner_results(
    conn: sqlite3.Connection,
    session_id: str,
    findings: list[Finding],
    scanners_used: list[str],
    session_errors: list[str],
) -> list[ScannerResult]:
    rows = conn.execute(
        "SELECT * FROM scanner_results WHERE session_id = ?", (session_id,)
    ).fetchall()
    if rows:
        return [
            ScannerResult(
                scanner_name=row["scanner_name"],
                findings=[f for f in findings if f.scanner == row["scanner_name"]],
                errors=json.loads(row["errors_json"]),
                metadata=json.loads(row["metadata_json"]),
            )
            for row in rows
        ]
    # Legacy rows predate the scanner_results table: rebuild from findings
    return [
        ScannerResult(
            scanner_name=name,
            findings=[f for f in findings if f.scanner == name],
            errors=[
                e.removeprefix(f"[{name}] ")
                for e in session_errors
                if e.startswith(f"[{name}]")
            ],
        )
        for name in scanners_used
    ]


def read_session(conn: sqlite3.Connection, session_id: str) -> ScanSession | None:
    scan_row = conn.execute(
        "SELECT * FROM scans WHERE session_id = ?", (session_id,)
    ).fetchone()
    if scan_row is None:
        return None

    findings = [
        _finding(row)
        for row in conn.execute(
            "SELECT * FROM findings WHERE session_id = ? ORDER BY id", (session_id,)
        )
    ]
    remediation_steps = [
        RemediationStep(
            title=row["title"],
            description=row["description"],
            effort=Effort(row["effort"]),
            impact=Severity(row["impact"]),
            finding_count=row["finding_count"],
            category=row["category"],
        )
        for row in conn.execute(
            "SELECT * FROM remediation_steps WHERE session_id = ? ORDER BY id",
            (session_id,),
        )
    ]
    enrichments, chains, triaged = read_llm_data(conn, session_id)
    scanners_used = json.loads(scan_row["scanners_used"])
    session_errors = json.loads(scan_row["errors"])
    target_data = json.loads(scan_row["target_json"] or "{}")

    return ScanSession(
        session_id=scan_row["session_id"],
        target=Target(base_url=target_data.get("base_url", scan_row["target_url"])),
        started_at=scan_row["started_at"],
        finished_at=scan_row["finished_at"],
        profile_name=scan_row["profile_name"],
        profile_intro=scan_row["profile_intro"],
        scanners_used=scanners_used,
        scanner_results=_scanner_results(
            conn, session_id, findings, scanners_used, session_errors
        ),
        all_findings=findings,
        remediation_steps=remediation_steps,
        risk_posture=RiskPosture(scan_row["risk_posture"]),
        risk_posture_text=scan_row["risk_posture_text"],
        errors=session_errors,
        llm_enrichments=enrichments,
        attack_chains=chains,
        triaged_findings=triaged,
        false_positive_assessments=json.loads(scan_row["false_positive_assessments"]),
        executive_priorities=scan_row["executive_priorities"],
        template_id=scan_row["template_id"],
    )
