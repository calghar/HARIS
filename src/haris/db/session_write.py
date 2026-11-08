import json
import sqlite3

from ..models import ScanSession
from .llm_data import write_llm_data


def _target_json(session: ScanSession) -> str:
    scope = session.target.scope
    return json.dumps(
        {
            "base_url": session.target.base_url,
            "scope": {
                "allowed_domains": scope.allowed_domains,
                "excluded_paths": scope.excluded_paths,
                "max_depth": scope.max_depth,
                "rate_limit_rps": scope.rate_limit_rps,
                "max_requests": scope.max_requests,
                "allowed_methods": scope.allowed_methods,
            },
        }
    )


def write_session(conn: sqlite3.Connection, session: ScanSession) -> None:
    sid = session.session_id
    conn.execute(
        """INSERT OR REPLACE INTO scans
           (session_id, target_url, profile_name, profile_intro,
            started_at, finished_at, scanners_used,
            risk_posture, risk_posture_text, errors, target_json,
            false_positive_assessments, executive_priorities,
            template_id)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (
            sid,
            session.target.base_url,
            session.profile_name,
            session.profile_intro,
            session.started_at,
            session.finished_at,
            json.dumps(session.scanners_used),
            session.risk_posture.value,
            session.risk_posture_text,
            json.dumps(session.errors),
            _target_json(session),
            json.dumps(session.false_positive_assessments),
            session.executive_priorities,
            session.template_id,
        ),
    )
    for table in ("findings", "remediation_steps", "scanner_results"):
        conn.execute(f"DELETE FROM {table} WHERE session_id = ?", (sid,))  # nosec B608
    conn.executemany(
        """INSERT INTO findings
           (session_id, finding_id, title, description,
            severity, confidence, owasp_category, cwe_id,
            url, parameter, method, evidence,
            request_example, response_snippet, remediation,
            references_json, scanner, found_at, tags_json)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        [
            (
                sid,
                f.finding_id,
                f.title,
                f.description,
                f.severity.value,
                f.confidence.value,
                f.owasp_category,
                f.cwe_id,
                f.url,
                f.parameter,
                f.method,
                f.evidence,
                f.request_example,
                f.response_snippet,
                f.remediation,
                json.dumps(f.references),
                f.scanner,
                f.found_at,
                json.dumps(f.tags),
            )
            for f in session.all_findings
        ],
    )
    conn.executemany(
        """INSERT INTO remediation_steps
           (session_id, title, description, effort,
            impact, finding_count, category)
           VALUES (?, ?, ?, ?, ?, ?, ?)""",
        [
            (
                sid,
                step.title,
                step.description,
                step.effort.value,
                step.impact.value,
                step.finding_count,
                step.category,
            )
            for step in session.remediation_steps
        ],
    )
    conn.executemany(
        """INSERT INTO scanner_results
           (session_id, scanner_name, errors_json, metadata_json)
           VALUES (?, ?, ?, ?)""",
        [
            (sid, sr.scanner_name, json.dumps(sr.errors), json.dumps(sr.metadata))
            for sr in session.scanner_results
        ],
    )
    write_llm_data(conn, session)
