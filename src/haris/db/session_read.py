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
    ScanState,
    Scope,
    Severity,
    Target,
)
from ..models.correlator import CorrelatedFinding
from ..models.verification import Suppression, Verification
from .llm_data import read_llm_data


def _finding(row: sqlite3.Row, base_url: str) -> Finding:
    finding = Finding(
        finding_id=row["finding_id"],
        observation_id=row["observation_id"],
        fingerprint=row["fingerprint"],
        vuln_class=row["vuln_class"],
        confidence_score=row["confidence_score"],
        verification=(
            Verification.model_validate_json(row["verification_json"])
            if row["verification_json"]
            else Verification()
        ),
        suppression=(
            Suppression.model_validate_json(row["suppression_json"])
            if row["suppression_json"]
            else None
        ),
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
        agent_annotation=row["agent_annotation"],
    )
    if not row["verification_json"]:
        # 0.6 row: identity is recomputed on read; the stored finding_id stays.
        from ..core.identity import identify

        finding.vuln_class, finding.fingerprint = identify(finding, base_url)
    return finding


def _correlated(raw: str) -> list[CorrelatedFinding]:
    return [
        CorrelatedFinding(
            canonical=Finding.from_dict(item["canonical"]),
            sources=[(s[0], s[1]) for s in item["sources"]],
            consensus_score=item["consensus_score"],
        )
        for item in json.loads(raw)
    ]


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


def _target(raw: str | None, fallback_url: str) -> Target:
    # A row with no scope key keeps Scope defaults (0.6.x and earlier).
    data = json.loads(raw or "{}")
    base_url = data.get("base_url") or fallback_url
    scope = data.get("scope")
    return (
        Target(base_url=base_url, scope=Scope.model_validate(scope))
        if isinstance(scope, dict)
        else Target(base_url=base_url)
    )


def read_session(conn: sqlite3.Connection, session_id: str) -> ScanSession | None:
    scan_row = conn.execute(
        "SELECT * FROM scans WHERE session_id = ?", (session_id,)
    ).fetchone()
    if scan_row is None:
        return None

    base_url = scan_row["target_url"]
    findings = [
        _finding(row, base_url)
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
    return ScanSession(
        session_id=scan_row["session_id"],
        target=_target(scan_row["target_json"], scan_row["target_url"]),
        started_at=scan_row["started_at"],
        finished_at=scan_row["finished_at"],
        profile_name=scan_row["profile_name"],
        profile_intro=scan_row["profile_intro"],
        scanners_used=scanners_used,
        scanner_results=_scanner_results(
            conn, session_id, findings, scanners_used, session_errors
        ),
        all_findings=findings,
        correlated=_correlated(scan_row["correlated_json"]),
        scan_state=ScanState(scan_row["scan_state"]),
        remediation_steps=remediation_steps,
        risk_posture=RiskPosture(scan_row["risk_posture"]),
        risk_posture_text=scan_row["risk_posture_text"],
        errors=session_errors,
        stage_log=json.loads(scan_row["stage_log"]),
        llm_enrichments=enrichments,
        attack_chains=chains,
        triaged_findings=triaged,
        false_positive_assessments=json.loads(scan_row["false_positive_assessments"]),
        executive_priorities=scan_row["executive_priorities"],
        template_id=scan_row["template_id"],
    )
