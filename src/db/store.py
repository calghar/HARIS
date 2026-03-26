import json
import logging
import sqlite3
from collections.abc import Generator
from contextlib import contextmanager
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from ..models import (
    Finding,
    RemediationStep,
    RiskPosture,
    ScannerResult,
    ScanSession,
    Target,
)
from ..models.enrichment import AttackChain, EnrichedFinding, TriagedFinding
from ..models.scan_config_template import ScanConfigTemplate

logger = logging.getLogger(__name__)

_SCHEMA_VERSION = 5

_SCHEMA_SQL = """\
CREATE TABLE IF NOT EXISTS schema_version (
    version INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS scans (
    session_id   TEXT PRIMARY KEY,
    target_url   TEXT NOT NULL,
    profile_name TEXT NOT NULL DEFAULT '',
    profile_intro TEXT NOT NULL DEFAULT '',
    started_at   TEXT NOT NULL DEFAULT '',
    finished_at  TEXT NOT NULL DEFAULT '',
    scanners_used TEXT NOT NULL DEFAULT '[]',
    risk_posture TEXT NOT NULL DEFAULT 'excellent',
    risk_posture_text TEXT NOT NULL DEFAULT '',
    errors       TEXT NOT NULL DEFAULT '[]',
    target_json  TEXT NOT NULL DEFAULT '{}'
);

CREATE TABLE IF NOT EXISTS findings (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id      TEXT NOT NULL REFERENCES scans(session_id) ON DELETE CASCADE,
    finding_id      TEXT NOT NULL,
    title           TEXT NOT NULL,
    description     TEXT NOT NULL DEFAULT '',
    severity        TEXT NOT NULL DEFAULT 'info',
    confidence      TEXT NOT NULL DEFAULT 'tentative',
    owasp_category  TEXT NOT NULL DEFAULT '',
    cwe_id          TEXT NOT NULL DEFAULT '',
    url             TEXT NOT NULL DEFAULT '',
    parameter       TEXT NOT NULL DEFAULT '',
    method          TEXT NOT NULL DEFAULT 'GET',
    evidence        TEXT NOT NULL DEFAULT '',
    request_example TEXT NOT NULL DEFAULT '',
    response_snippet TEXT NOT NULL DEFAULT '',
    remediation     TEXT NOT NULL DEFAULT '',
    references_json TEXT NOT NULL DEFAULT '[]',
    scanner         TEXT NOT NULL DEFAULT '',
    found_at        TEXT NOT NULL DEFAULT '',
    tags_json       TEXT NOT NULL DEFAULT '[]',
    UNIQUE(session_id, finding_id)
);

CREATE TABLE IF NOT EXISTS remediation_steps (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id    TEXT NOT NULL REFERENCES scans(session_id) ON DELETE CASCADE,
    title         TEXT NOT NULL,
    description   TEXT NOT NULL DEFAULT '',
    effort        TEXT NOT NULL DEFAULT 'moderate',
    impact        TEXT NOT NULL DEFAULT 'medium',
    finding_count INTEGER NOT NULL DEFAULT 0,
    category      TEXT NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_findings_session ON findings(session_id);
CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);
CREATE INDEX IF NOT EXISTS idx_remediation_session ON remediation_steps(session_id);
"""

_SCHEMA_V2_SQL = """\
CREATE TABLE IF NOT EXISTS llm_enrichments (
    id                      INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id              TEXT NOT NULL
        REFERENCES scans(session_id) ON DELETE CASCADE,
    finding_id              TEXT NOT NULL,
    attack_narrative        TEXT NOT NULL DEFAULT '',
    business_impact_assessment TEXT NOT NULL DEFAULT '',
    exploitation_complexity TEXT NOT NULL DEFAULT '',
    false_positive_likelihood TEXT NOT NULL DEFAULT '',
    related_cwes            TEXT NOT NULL DEFAULT '[]',
    attack_chain_position   TEXT NOT NULL DEFAULT '',
    variant_suggestions     TEXT NOT NULL DEFAULT '[]',
    UNIQUE(session_id, finding_id)
);

CREATE TABLE IF NOT EXISTS attack_chains (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id      TEXT NOT NULL REFERENCES scans(session_id) ON DELETE CASCADE,
    chain_id        TEXT NOT NULL,
    name            TEXT NOT NULL,
    description     TEXT NOT NULL DEFAULT '',
    finding_ids     TEXT NOT NULL DEFAULT '[]',
    total_impact    TEXT NOT NULL DEFAULT '',
    likelihood      TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS triaged_findings (
    id                   INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id           TEXT NOT NULL REFERENCES scans(session_id) ON DELETE CASCADE,
    finding_id           TEXT NOT NULL,
    original_severity    TEXT NOT NULL DEFAULT 'info',
    adjusted_severity    TEXT NOT NULL DEFAULT 'info',
    exploitability_score INTEGER NOT NULL DEFAULT 5,
    business_priority    INTEGER NOT NULL DEFAULT 5,
    triage_rationale     TEXT NOT NULL DEFAULT '',
    recommended_timeline TEXT NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_llm_enrichments_session ON llm_enrichments(session_id);
CREATE INDEX IF NOT EXISTS idx_attack_chains_session ON attack_chains(session_id);
CREATE INDEX IF NOT EXISTS idx_triaged_findings_session ON triaged_findings(session_id);
"""

_SCHEMA_V3_SQL = """\
ALTER TABLE scans ADD COLUMN false_positive_assessments TEXT NOT NULL DEFAULT '[]';
ALTER TABLE scans ADD COLUMN executive_priorities TEXT NOT NULL DEFAULT '';
"""

_SCHEMA_V4_SQL = """\
CREATE TABLE IF NOT EXISTS scan_config_templates (
    template_id    TEXT PRIMARY KEY,
    name           TEXT NOT NULL,
    description    TEXT NOT NULL DEFAULT '',
    profile        TEXT NOT NULL DEFAULT 'quick',
    rate_limit_rps REAL NOT NULL DEFAULT 10.0,
    max_requests   INTEGER NOT NULL DEFAULT 10000,
    excluded_paths TEXT NOT NULL DEFAULT '[]',
    auth_method    TEXT NOT NULL DEFAULT 'none',
    report_formats TEXT NOT NULL DEFAULT '["markdown","json"]',
    llm_enrichment INTEGER NOT NULL DEFAULT 0,
    llm_backend    TEXT NOT NULL DEFAULT '',
    scanner_options TEXT NOT NULL DEFAULT '{}',
    tags           TEXT NOT NULL DEFAULT '[]',
    is_default     INTEGER NOT NULL DEFAULT 0,
    created_at     TEXT NOT NULL DEFAULT '',
    updated_at     TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_sct_name ON scan_config_templates(name);
ALTER TABLE scans ADD COLUMN template_id TEXT NOT NULL DEFAULT '';
CREATE INDEX IF NOT EXISTS idx_scans_template ON scans(template_id);
"""


_SCHEMA_V5_SQL = """\
CREATE TABLE IF NOT EXISTS scanner_results (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id    TEXT NOT NULL REFERENCES scans(session_id) ON DELETE CASCADE,
    scanner_name  TEXT NOT NULL,
    errors_json   TEXT NOT NULL DEFAULT '[]',
    metadata_json TEXT NOT NULL DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS idx_scanner_results_session ON scanner_results(session_id);
"""


class ScanStore:
    """SQLite storage for scan sessions and findings.

    Thread-safe for single-writer / multiple-reader access.
    """

    def __init__(self, db_path: str | Path = "data/HARIS.db") -> None:
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    @contextmanager
    def _connect(self) -> Generator[sqlite3.Connection]:
        """Yield a database connection with automatic commit/rollback.

        On successful exit the transaction is committed. If an exception
        propagates out of the ``with`` block the transaction is rolled
        back before the connection is closed.
        """
        conn = sqlite3.connect(str(self.db_path), timeout=10)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA foreign_keys=ON")
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def _init_db(self) -> None:
        """Create tables if they don't exist and apply migrations."""
        with self._connect() as conn:
            conn.executescript(_SCHEMA_SQL)
            # Check/set schema version
            row = conn.execute("SELECT version FROM schema_version LIMIT 1").fetchone()
            if row is None:
                conn.execute(
                    "INSERT INTO schema_version (version) VALUES (?)",
                    (_SCHEMA_VERSION,),
                )
                conn.executescript(_SCHEMA_V2_SQL)
                conn.executescript(_SCHEMA_V3_SQL)
                conn.executescript(_SCHEMA_V4_SQL)
                conn.executescript(_SCHEMA_V5_SQL)
            else:
                current = row["version"]
                if current < 2:
                    conn.executescript(_SCHEMA_V2_SQL)
                if current < 3:
                    conn.executescript(_SCHEMA_V3_SQL)
                if current < 4:
                    conn.executescript(_SCHEMA_V4_SQL)
                if current < 5:
                    conn.executescript(_SCHEMA_V5_SQL)
                if current < _SCHEMA_VERSION:
                    conn.execute(
                        "UPDATE schema_version SET version = ?",
                        (_SCHEMA_VERSION,),
                    )
        self._seed_default_templates()
        logger.debug("Database initialised at %s", self.db_path)

    # Write operations

    def save_session(self, session: ScanSession) -> None:
        """Persist a complete scan session (upsert)."""
        with self._connect() as conn:
            # Serialize target as JSON for reconstruction
            target_json = json.dumps(
                {
                    "base_url": session.target.base_url,
                    "scope": {
                        "allowed_domains": session.target.scope.allowed_domains,
                        "excluded_paths": session.target.scope.excluded_paths,
                        "max_depth": session.target.scope.max_depth,
                        "rate_limit_rps": session.target.scope.rate_limit_rps,
                        "max_requests": session.target.scope.max_requests,
                        "allowed_methods": session.target.scope.allowed_methods,
                    },
                }
            )

            conn.execute(
                """INSERT OR REPLACE INTO scans
                   (session_id, target_url, profile_name, profile_intro,
                    started_at, finished_at, scanners_used,
                    risk_posture, risk_posture_text, errors, target_json,
                    false_positive_assessments, executive_priorities,
                    template_id)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    session.session_id,
                    session.target.base_url,
                    session.profile_name,
                    session.profile_intro,
                    session.started_at,
                    session.finished_at,
                    json.dumps(session.scanners_used),
                    session.risk_posture.value,
                    session.risk_posture_text,
                    json.dumps(session.errors),
                    target_json,
                    json.dumps(session.false_positive_assessments),
                    session.executive_priorities,
                    session.template_id,
                ),
            )

            # Delete existing findings/remediation for this session (upsert)
            conn.execute(
                "DELETE FROM findings WHERE session_id = ?",
                (session.session_id,),
            )
            conn.execute(
                "DELETE FROM remediation_steps WHERE session_id = ?",
                (session.session_id,),
            )

            # Insert findings
            for f in session.all_findings:
                conn.execute(
                    """INSERT INTO findings
                       (session_id, finding_id, title, description,
                        severity, confidence, owasp_category, cwe_id,
                        url, parameter, method, evidence,
                        request_example, response_snippet, remediation,
                        references_json, scanner, found_at, tags_json)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
                              ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (
                        session.session_id,
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
                    ),
                )

            # Insert remediation steps
            for step in session.remediation_steps:
                conn.execute(
                    """INSERT INTO remediation_steps
                       (session_id, title, description, effort,
                        impact, finding_count, category)
                       VALUES (?, ?, ?, ?, ?, ?, ?)""",
                    (
                        session.session_id,
                        step.title,
                        step.description,
                        step.effort.value,
                        step.impact.value,
                        step.finding_count,
                        step.category,
                    ),
                )

            # Insert LLM enrichments
            conn.execute(
                "DELETE FROM llm_enrichments WHERE session_id = ?",
                (session.session_id,),
            )
            for fid, e in session.llm_enrichments.items():
                conn.execute(
                    """INSERT INTO llm_enrichments
                       (session_id, finding_id, attack_narrative,
                        business_impact_assessment,
                        exploitation_complexity,
                        false_positive_likelihood, related_cwes,
                        attack_chain_position, variant_suggestions)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (
                        session.session_id,
                        fid,
                        e.attack_narrative,
                        e.business_impact_assessment,
                        e.exploitation_complexity,
                        e.false_positive_likelihood,
                        json.dumps(e.related_cwes),
                        e.attack_chain_position,
                        json.dumps(e.variant_suggestions),
                    ),
                )

            # Insert attack chains
            conn.execute(
                "DELETE FROM attack_chains WHERE session_id = ?",
                (session.session_id,),
            )
            for chain in session.attack_chains:
                conn.execute(
                    """INSERT INTO attack_chains
                       (session_id, chain_id, name, description,
                        finding_ids, total_impact, likelihood)
                       VALUES (?, ?, ?, ?, ?, ?, ?)""",
                    (
                        session.session_id,
                        chain.chain_id,
                        chain.name,
                        chain.description,
                        json.dumps(chain.finding_ids),
                        chain.total_impact,
                        chain.likelihood,
                    ),
                )

            # Insert triaged findings
            conn.execute(
                "DELETE FROM triaged_findings WHERE session_id = ?",
                (session.session_id,),
            )
            for tf in session.triaged_findings:
                conn.execute(
                    """INSERT INTO triaged_findings
                       (session_id, finding_id, original_severity,
                        adjusted_severity, exploitability_score,
                        business_priority, triage_rationale,
                        recommended_timeline)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                    (
                        session.session_id,
                        tf.finding_id,
                        tf.original_severity.value,
                        tf.adjusted_severity.value,
                        tf.exploitability_score,
                        tf.business_priority,
                        tf.triage_rationale,
                        tf.recommended_timeline,
                    ),
                )

            # Insert scanner results
            conn.execute(
                "DELETE FROM scanner_results WHERE session_id = ?",
                (session.session_id,),
            )
            for sr in session.scanner_results:
                conn.execute(
                    """INSERT INTO scanner_results
                       (session_id, scanner_name, errors_json,
                        metadata_json)
                       VALUES (?, ?, ?, ?)""",
                    (
                        session.session_id,
                        sr.scanner_name,
                        json.dumps(sr.errors),
                        json.dumps(sr.metadata),
                    ),
                )

        logger.info(
            "Saved session %s (%d findings, %d remediation steps)",
            session.session_id,
            len(session.all_findings),
            len(session.remediation_steps),
        )

    def delete_session(self, session_id: str) -> bool:
        """Delete a session and all related data. Returns True if found."""
        with self._connect() as conn:
            cursor = conn.execute(
                "DELETE FROM scans WHERE session_id = ?",
                (session_id,),
            )
            return cursor.rowcount > 0

    # Read operations

    def list_sessions(self) -> list[dict[str, Any]]:
        """Return a summary list of all stored scan sessions."""
        with self._connect() as conn:
            rows = conn.execute(
                """SELECT s.session_id, s.target_url, s.profile_name,
                          s.started_at, s.risk_posture, s.template_id,
                          COUNT(f.id) AS finding_count
                   FROM scans s
                   LEFT JOIN findings f ON f.session_id = s.session_id
                   GROUP BY s.session_id
                   ORDER BY s.started_at DESC"""
            ).fetchall()

        return [
            {
                "session_id": row["session_id"],
                "target_url": row["target_url"],
                "profile_name": row["profile_name"],
                "started_at": row["started_at"],
                "risk_posture": row["risk_posture"],
                "finding_count": row["finding_count"],
                "template_id": row["template_id"],
            }
            for row in rows
        ]

    def load_session(self, session_id: str) -> ScanSession | None:
        """Load a full scan session by ID. Returns None if not found."""
        with self._connect() as conn:
            scan_row = conn.execute(
                "SELECT * FROM scans WHERE session_id = ?",
                (session_id,),
            ).fetchone()

            if scan_row is None:
                return None

            finding_rows = conn.execute(
                "SELECT * FROM findings WHERE session_id = ? ORDER BY id",
                (session_id,),
            ).fetchall()

            remediation_rows = conn.execute(
                "SELECT * FROM remediation_steps WHERE session_id = ? ORDER BY id",
                (session_id,),
            ).fetchall()

            enrichment_rows = conn.execute(
                "SELECT * FROM llm_enrichments WHERE session_id = ?",
                (session_id,),
            ).fetchall()

            chain_rows = conn.execute(
                "SELECT * FROM attack_chains WHERE session_id = ?",
                (session_id,),
            ).fetchall()

            triage_rows = conn.execute(
                "SELECT * FROM triaged_findings WHERE session_id = ?",
                (session_id,),
            ).fetchall()

            scanner_result_rows = conn.execute(
                "SELECT * FROM scanner_results WHERE session_id = ?",
                (session_id,),
            ).fetchall()

        # Reconstruct target
        target_data = json.loads(scan_row["target_json"] or "{}")
        target = Target(base_url=target_data.get("base_url", scan_row["target_url"]))

        # Reconstruct findings
        from ..models import Confidence, Severity

        findings = []
        for row in finding_rows:
            findings.append(
                Finding(
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
            )

        # Reconstruct remediation steps
        from ..models import Effort
        from ..models import Severity as FindingSeverity

        remediation_steps = []
        for row in remediation_rows:
            remediation_steps.append(
                RemediationStep(
                    title=row["title"],
                    description=row["description"],
                    effort=Effort(row["effort"]),
                    impact=FindingSeverity(row["impact"]),
                    finding_count=row["finding_count"],
                    category=row["category"],
                )
            )

        # Reconstruct LLM enrichments
        llm_enrichments: dict[str, EnrichedFinding] = {}
        for row in enrichment_rows:
            llm_enrichments[row["finding_id"]] = EnrichedFinding(
                finding_id=row["finding_id"],
                attack_narrative=row["attack_narrative"],
                business_impact_assessment=row["business_impact_assessment"],
                exploitation_complexity=row["exploitation_complexity"],
                false_positive_likelihood=row["false_positive_likelihood"],
                related_cwes=json.loads(row["related_cwes"]),
                attack_chain_position=row["attack_chain_position"],
                variant_suggestions=json.loads(row["variant_suggestions"]),
            )

        attack_chains = [
            AttackChain(
                chain_id=row["chain_id"],
                name=row["name"],
                description=row["description"],
                finding_ids=json.loads(row["finding_ids"]),
                total_impact=row["total_impact"],
                likelihood=row["likelihood"],
            )
            for row in chain_rows
        ]

        triaged_findings = [
            TriagedFinding(
                finding_id=row["finding_id"],
                original_severity=Severity(row["original_severity"]),
                adjusted_severity=Severity(row["adjusted_severity"]),
                exploitability_score=row["exploitability_score"],
                business_priority=row["business_priority"],
                triage_rationale=row["triage_rationale"],
                recommended_timeline=row["recommended_timeline"],
            )
            for row in triage_rows
        ]

        # Reconstruct scanner results
        scanners_used = json.loads(scan_row["scanners_used"])
        session_errors = json.loads(scan_row["errors"])

        if scanner_result_rows:
            # New-style: load from dedicated table
            scanner_results = []
            for row in scanner_result_rows:
                name = row["scanner_name"]
                sr_findings = [f for f in findings if f.scanner == name]
                scanner_results.append(
                    ScannerResult(
                        scanner_name=name,
                        findings=sr_findings,
                        errors=json.loads(row["errors_json"]),
                        metadata=json.loads(row["metadata_json"]),
                    )
                )
        else:
            # Legacy fallback: reconstruct from findings + scanners_used
            scanner_results = []
            for name in scanners_used:
                sr_findings = [f for f in findings if f.scanner == name]
                sr_errors = [
                    e.removeprefix(f"[{name}] ")
                    for e in session_errors
                    if e.startswith(f"[{name}]")
                ]
                scanner_results.append(
                    ScannerResult(
                        scanner_name=name,
                        findings=sr_findings,
                        errors=sr_errors,
                    )
                )

        return ScanSession(
            session_id=scan_row["session_id"],
            target=target,
            started_at=scan_row["started_at"],
            finished_at=scan_row["finished_at"],
            profile_name=scan_row["profile_name"],
            profile_intro=scan_row["profile_intro"],
            scanners_used=scanners_used,
            scanner_results=scanner_results,
            all_findings=findings,
            remediation_steps=remediation_steps,
            risk_posture=RiskPosture(scan_row["risk_posture"]),
            risk_posture_text=scan_row["risk_posture_text"],
            errors=session_errors,
            llm_enrichments=llm_enrichments,
            attack_chains=attack_chains,
            triaged_findings=triaged_findings,
            false_positive_assessments=json.loads(
                scan_row["false_positive_assessments"]
                if "false_positive_assessments" in scan_row.keys()  # noqa: SIM118
                else "[]"
            ),
            executive_priorities=(
                scan_row["executive_priorities"]
                if "executive_priorities" in scan_row.keys()  # noqa: SIM118
                else ""
            ),
            template_id=(
                scan_row["template_id"]
                if "template_id" in scan_row.keys()  # noqa: SIM118
                else ""
            ),
        )

    def get_findings(
        self,
        session_id: str,
        *,
        severity: str | None = None,
        owasp_category: str | None = None,
    ) -> list[dict[str, Any]]:
        """Query findings with optional filters."""
        query = "SELECT * FROM findings WHERE session_id = ?"
        params: list[Any] = [session_id]

        if severity:
            query += " AND severity = ?"
            params.append(severity)

        if owasp_category:
            query += " AND owasp_category LIKE ?"
            params.append(f"%{owasp_category}%")

        query += " ORDER BY id"

        with self._connect() as conn:
            rows = conn.execute(query, params).fetchall()

        return [
            {
                "finding_id": row["finding_id"],
                "title": row["title"],
                "description": row["description"],
                "severity": row["severity"],
                "confidence": row["confidence"],
                "owasp_category": row["owasp_category"],
                "cwe_id": row["cwe_id"],
                "url": row["url"],
                "parameter": row["parameter"],
                "scanner": row["scanner"],
                "remediation": row["remediation"],
            }
            for row in rows
        ]

    def session_exists(self, session_id: str) -> bool:
        """Check if a session exists in the database."""
        with self._connect() as conn:
            row = conn.execute(
                "SELECT 1 FROM scans WHERE session_id = ? LIMIT 1",
                (session_id,),
            ).fetchone()
            return row is not None

    # Aggregation queries (dashboard, websites, trends)

    @staticmethod
    def _hostname(url: str) -> str:
        return urlparse(url).hostname or "unknown"

    def dashboard_summary(self) -> dict[str, Any]:
        """Return high-level dashboard statistics."""
        with self._connect() as conn:
            total_scans = conn.execute("SELECT COUNT(*) AS c FROM scans").fetchone()[
                "c"
            ]

            urls = conn.execute("SELECT DISTINCT target_url FROM scans").fetchall()

            critical_findings = conn.execute(
                """SELECT f.finding_id, f.title, f.severity, f.url,
                          s.session_id, s.target_url
                   FROM findings f
                   JOIN scans s ON s.session_id = f.session_id
                   WHERE f.severity IN ('critical', 'high')
                   ORDER BY s.started_at DESC
                   LIMIT 10"""
            ).fetchall()

            latest = conn.execute(
                "SELECT started_at FROM scans ORDER BY started_at DESC LIMIT 1"
            ).fetchone()

            # Per-session summaries for website grouping
            session_rows = conn.execute(
                """SELECT s.session_id, s.target_url, s.started_at,
                          s.risk_posture, COUNT(f.id) AS finding_count
                   FROM scans s
                   LEFT JOIN findings f ON f.session_id = s.session_id
                   GROUP BY s.session_id
                   ORDER BY s.started_at DESC"""
            ).fetchall()

        distinct_hosts = len({self._hostname(r["target_url"]) for r in urls})

        # Track latest scan per website for recent_websites
        seen_hosts: set[str] = set()
        for row in session_rows:
            host = self._hostname(row["target_url"])
            if host not in seen_hosts:
                seen_hosts.add(host)

        # Recent critical findings as dicts
        recent_findings = [
            {
                "finding_id": r["finding_id"],
                "title": r["title"],
                "severity": r["severity"],
                "url": r["url"],
                "session_id": r["session_id"],
                "target_url": r["target_url"],
            }
            for r in critical_findings
        ]

        # Recent websites (up to 5)
        seen: set[str] = set()
        recent_websites: list[dict[str, Any]] = []
        for row in session_rows:
            host = self._hostname(row["target_url"])
            if host not in seen:
                seen.add(host)
                recent_websites.append(
                    {
                        "hostname": host,
                        "risk_posture": row["risk_posture"],
                        "finding_count": row["finding_count"],
                        "last_scanned": row["started_at"],
                    }
                )
                if len(recent_websites) >= 5:
                    break

        return {
            "total_websites": distinct_hosts,
            "total_scans": total_scans,
            "open_critical_high": len(recent_findings),
            "latest_scan_time": latest["started_at"] if latest else "",
            "recent_findings": recent_findings,
            "recent_websites": recent_websites,
        }

    def list_websites(self) -> list[dict[str, Any]]:
        """Return distinct hostnames with scan counts and latest risk."""
        with self._connect() as conn:
            rows = conn.execute(
                """SELECT s.session_id, s.target_url, s.started_at,
                          s.risk_posture, COUNT(f.id) AS finding_count
                   FROM scans s
                   LEFT JOIN findings f ON f.session_id = s.session_id
                   GROUP BY s.session_id
                   ORDER BY s.started_at DESC"""
            ).fetchall()

        websites: dict[str, dict[str, Any]] = {}
        for row in rows:
            host = self._hostname(row["target_url"])
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

    def get_scans_for_hostname(self, hostname: str) -> list[dict[str, Any]]:
        """Return all scans for a given hostname, newest first."""
        with self._connect() as conn:
            rows = conn.execute(
                """SELECT s.session_id, s.target_url, s.profile_name,
                          s.started_at, s.risk_posture, s.template_id,
                          s.scanners_used,
                          COUNT(f.id) AS finding_count
                   FROM scans s
                   LEFT JOIN findings f ON f.session_id = s.session_id
                   GROUP BY s.session_id
                   ORDER BY s.started_at DESC"""
            ).fetchall()

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
            for row in rows
            if self._hostname(row["target_url"]) == hostname
        ]

    def get_severity_trends(self, hostname: str) -> dict[str, Any]:
        """Return per-scan severity counts formatted for Chart.js."""
        with self._connect() as conn:
            rows = conn.execute(
                """SELECT s.session_id, s.started_at, s.target_url,
                          f.severity, COUNT(f.id) AS count
                   FROM scans s
                   JOIN findings f ON f.session_id = s.session_id
                   GROUP BY s.session_id, f.severity
                   ORDER BY s.started_at ASC"""
            ).fetchall()

        # Filter by hostname and pivot into chart-friendly format
        scans_order: list[str] = []  # session_ids in order
        scan_dates: dict[str, str] = {}
        severity_data: dict[str, dict[str, int]] = {}

        for row in rows:
            if self._hostname(row["target_url"]) != hostname:
                continue
            sid = row["session_id"]
            if sid not in scan_dates:
                scans_order.append(sid)
                scan_dates[sid] = row["started_at"][:10]  # date only
                severity_data[sid] = {}
            severity_data[sid][row["severity"]] = row["count"]

        labels = [scan_dates[sid] for sid in scans_order]
        severities = ["critical", "high", "medium", "low", "info"]
        datasets = {
            sev: [severity_data.get(sid, {}).get(sev, 0) for sid in scans_order]
            for sev in severities
        }

        # Latest scan severity distribution
        latest_severity = dict.fromkeys(severities, 0)
        if scans_order:
            latest_severity.update(severity_data.get(scans_order[-1], {}))

        return {
            "labels": labels,
            "datasets": datasets,
            "latest_severity": latest_severity,
        }

    def list_sessions_paginated(
        self,
        *,
        page: int = 1,
        per_page: int = 20,
        hostname: str | None = None,
        severity: str | None = None,
        date_from: str | None = None,
        date_to: str | None = None,
        template_id: str | None = None,
        scanner: str | None = None,
    ) -> tuple[list[dict[str, Any]], int]:
        """Return paginated, filtered scan sessions."""
        base = """FROM scans s
                  LEFT JOIN findings f ON f.session_id = s.session_id"""
        where_clauses: list[str] = []
        params: list[Any] = []

        if hostname:
            where_clauses.append("s.target_url LIKE ?")
            params.append(f"%{hostname}%")

        if date_from:
            where_clauses.append("s.started_at >= ?")
            params.append(date_from)

        if date_to:
            where_clauses.append("s.started_at <= ?")
            params.append(date_to + "T23:59:59")

        if severity:
            where_clauses.append(
                """EXISTS (SELECT 1 FROM findings f2
                          WHERE f2.session_id = s.session_id
                          AND f2.severity = ?)"""
            )
            params.append(severity)

        if template_id:
            where_clauses.append("s.template_id = ?")
            params.append(template_id)

        if scanner:
            where_clauses.append("s.scanners_used LIKE ?")
            params.append(f'%"{scanner}"%')

        where_sql = ""
        if where_clauses:
            where_sql = " WHERE " + " AND ".join(where_clauses)

        with self._connect() as conn:
            count_row = conn.execute(
                f"SELECT COUNT(DISTINCT s.session_id) AS c {base}{where_sql}",
                params,
            ).fetchone()
            total = count_row["c"]

            offset = (page - 1) * per_page
            rows = conn.execute(
                f"""SELECT s.session_id, s.target_url, s.profile_name,
                           s.started_at, s.risk_posture, s.template_id,
                           COUNT(f.id) AS finding_count
                    {base}{where_sql}
                    GROUP BY s.session_id
                    ORDER BY s.started_at DESC
                    LIMIT ? OFFSET ?""",
                [*params, per_page, offset],
            ).fetchall()

        return (
            [
                {
                    "session_id": row["session_id"],
                    "target_url": row["target_url"],
                    "profile_name": row["profile_name"],
                    "started_at": row["started_at"],
                    "risk_posture": row["risk_posture"],
                    "finding_count": row["finding_count"],
                    "template_id": row["template_id"],
                }
                for row in rows
            ],
            total,
        )

    # Scan configuration templates

    def save_scan_config_template(self, tpl: ScanConfigTemplate) -> None:
        """Insert or update a scan configuration template."""
        with self._connect() as conn:
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

    def get_scan_config_template(
        self,
        template_id: str,
    ) -> ScanConfigTemplate | None:
        """Load a single scan config template by ID."""
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM scan_config_templates WHERE template_id = ?",
                (template_id,),
            ).fetchone()

        if row is None:
            return None
        return self._row_to_template(row)

    def list_scan_config_templates(self) -> list[dict[str, Any]]:
        """Return all scan config templates, ordered by name."""
        with self._connect() as conn:
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

    def delete_scan_config_template(self, template_id: str) -> bool:
        """Delete a scan config template. Returns True if found."""
        with self._connect() as conn:
            cursor = conn.execute(
                "DELETE FROM scan_config_templates WHERE template_id = ?",
                (template_id,),
            )
            return cursor.rowcount > 0

    def set_default_scan_config_template(self, template_id: str) -> None:
        """Mark one template as default, clearing any previous default."""
        with self._connect() as conn:
            conn.execute("UPDATE scan_config_templates SET is_default = 0")
            conn.execute(
                "UPDATE scan_config_templates SET is_default = 1 WHERE template_id = ?",
                (template_id,),
            )

    def get_default_scan_config_template(
        self,
    ) -> ScanConfigTemplate | None:
        """Return the default template, or None."""
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM scan_config_templates WHERE is_default = 1"
            ).fetchone()

        if row is None:
            return None
        return self._row_to_template(row)

    @staticmethod
    def _row_to_template(row: sqlite3.Row) -> ScanConfigTemplate:
        """Convert a DB row to a ScanConfigTemplate."""
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

    # Seed default templates

    def _seed_default_templates(self) -> None:
        """Populate built-in scan config templates on first run."""
        with self._connect() as conn:
            count = conn.execute(
                "SELECT COUNT(*) AS c FROM scan_config_templates"
            ).fetchone()["c"]

        if count > 0:
            return

        now = ""  # Will be set by caller if needed
        defaults = [
            ScanConfigTemplate(
                template_id="builtin-01",
                name="Quick Surface Scan",
                description=(
                    "Fast built-in checks only. Good for first look or CI gates."
                ),
                profile="quick",
                rate_limit_rps=10.0,
                max_requests=10_000,
                llm_enrichment=False,
                scanner_options={},
                tags=["built-in", "ci", "fast"],
                is_default=True,
                created_at=now,
                updated_at=now,
            ),
            ScanConfigTemplate(
                template_id="builtin-02",
                name="Pre-Launch Audit",
                description=(
                    "Comprehensive scan before go-live. Built-in checks "
                    "plus network scanners."
                ),
                profile="pre-launch",
                rate_limit_rps=10.0,
                max_requests=10_000,
                llm_enrichment=True,
                scanner_options={
                    "nmap": {
                        "ports": "80,443,8080,8443,8000,3000,9090",
                        "script_categories": ["default", "safe", "vuln"],
                    },
                    "wapiti": {
                        "scope": "folder",
                        "modules": "all",
                        "max_links": 500,
                    },
                },
                tags=["built-in", "pre-launch"],
                created_at=now,
                updated_at=now,
            ),
            ScanConfigTemplate(
                template_id="builtin-03",
                name="Full OWASP Top 10",
                description=(
                    "Maximum coverage with all scanners including "
                    "active injection testing."
                ),
                profile="full",
                rate_limit_rps=5.0,
                max_requests=50_000,
                llm_enrichment=True,
                scanner_options={
                    "nuclei": {
                        "template_dirs": [
                            "http/exposures",
                            "http/exposed-panels",
                            "http/vulnerabilities",
                            "http/default-logins",
                            "http/takeovers",
                            "dast",
                        ],
                        "severity": [
                            "critical",
                            "high",
                            "medium",
                            "low",
                            "info",
                        ],
                        "exclude_tags": ["dos", "fuzz"],
                        "rate_limit": 100,
                    },
                    "nikto": {
                        "tuning": ["1", "2", "3", "b", "d", "e"],
                        "plugins": [
                            "@@DEFAULT",
                            "shellshock",
                            "headers",
                            "springboot",
                        ],
                    },
                    "wapiti": {
                        "scope": "domain",
                        "modules": "all",
                        "max_scan_time": 900,
                        "max_links": 1000,
                    },
                    "nmap": {
                        "ports": ("80,443,8080,8443,8000,8888,3000,5000,9090,9443"),
                        "script_categories": [
                            "default",
                            "safe",
                            "vuln",
                            "discovery",
                        ],
                    },
                },
                tags=["built-in", "comprehensive", "owasp"],
                created_at=now,
                updated_at=now,
            ),
            ScanConfigTemplate(
                template_id="builtin-04",
                name="Regression Check",
                description=(
                    "Lightweight post-deployment check. Headers, TLS, "
                    "and misconfiguration only."
                ),
                profile="regression",
                rate_limit_rps=20.0,
                max_requests=5_000,
                llm_enrichment=False,
                scanner_options={
                    "misc_checks": {"check_sensitive_paths": False},
                    "tls_checks": {"cert_expiry_warn_days": 30},
                },
                tags=["built-in", "ci", "fast", "regression"],
                created_at=now,
                updated_at=now,
            ),
            ScanConfigTemplate(
                template_id="builtin-05",
                name="Compliance Audit",
                description=(
                    "Focused on SOC 2 / ISO 27001 / PCI-DSS control verification."
                ),
                profile="compliance",
                rate_limit_rps=10.0,
                max_requests=20_000,
                llm_enrichment=True,
                scanner_options={
                    "nmap": {
                        "ports": "80,443,8080,8443,22,3389",
                        "script_categories": [
                            "default",
                            "safe",
                            "vuln",
                            "auth",
                        ],
                    },
                    "tls_checks": {"cert_expiry_warn_days": 60},
                    "info_disclosure": {
                        "check_error_pages": True,
                        "check_version_endpoints": True,
                    },
                },
                tags=["built-in", "compliance", "audit"],
                created_at=now,
                updated_at=now,
            ),
        ]

        for tpl in defaults:
            self.save_scan_config_template(tpl)
