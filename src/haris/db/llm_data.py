import json
import sqlite3

from ..models import ScanSession, Severity
from ..models.enrichment import AttackChain, EnrichedFinding, TriagedFinding


def write_llm_data(conn: sqlite3.Connection, session: ScanSession) -> None:
    sid = session.session_id
    for table in ("llm_enrichments", "attack_chains", "triaged_findings"):
        conn.execute(f"DELETE FROM {table} WHERE session_id = ?", (sid,))  # nosec B608
    conn.executemany(
        """INSERT INTO llm_enrichments
           (session_id, finding_id, attack_narrative,
            business_impact_assessment, exploitation_complexity,
            false_positive_likelihood, related_cwes,
            attack_chain_position, variant_suggestions)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        [
            (
                sid,
                fid,
                e.attack_narrative,
                e.business_impact_assessment,
                e.exploitation_complexity,
                e.false_positive_likelihood,
                json.dumps(e.related_cwes),
                e.attack_chain_position,
                json.dumps(e.variant_suggestions),
            )
            for fid, e in session.llm_enrichments.items()
        ],
    )
    conn.executemany(
        """INSERT INTO attack_chains
           (session_id, chain_id, name, description,
            finding_ids, total_impact, likelihood)
           VALUES (?, ?, ?, ?, ?, ?, ?)""",
        [
            (
                sid,
                c.chain_id,
                c.name,
                c.description,
                json.dumps(c.finding_ids),
                c.total_impact,
                c.likelihood,
            )
            for c in session.attack_chains
        ],
    )
    conn.executemany(
        """INSERT INTO triaged_findings
           (session_id, finding_id, original_severity, adjusted_severity,
            exploitability_score, business_priority, triage_rationale,
            recommended_timeline)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
        [
            (
                sid,
                t.finding_id,
                t.original_severity.value,
                t.adjusted_severity.value,
                t.exploitability_score,
                t.business_priority,
                t.triage_rationale,
                t.recommended_timeline,
            )
            for t in session.triaged_findings
        ],
    )


def read_llm_data(
    conn: sqlite3.Connection, session_id: str
) -> tuple[dict[str, EnrichedFinding], list[AttackChain], list[TriagedFinding]]:
    enrichments = {
        row["finding_id"]: EnrichedFinding(
            finding_id=row["finding_id"],
            attack_narrative=row["attack_narrative"],
            business_impact_assessment=row["business_impact_assessment"],
            exploitation_complexity=row["exploitation_complexity"],
            false_positive_likelihood=row["false_positive_likelihood"],
            related_cwes=json.loads(row["related_cwes"]),
            attack_chain_position=row["attack_chain_position"],
            variant_suggestions=json.loads(row["variant_suggestions"]),
        )
        for row in conn.execute(
            "SELECT * FROM llm_enrichments WHERE session_id = ?", (session_id,)
        )
    }
    chains = [
        AttackChain(
            chain_id=row["chain_id"],
            name=row["name"],
            description=row["description"],
            finding_ids=json.loads(row["finding_ids"]),
            total_impact=row["total_impact"],
            likelihood=row["likelihood"],
        )
        for row in conn.execute(
            "SELECT * FROM attack_chains WHERE session_id = ?", (session_id,)
        )
    ]
    triaged = [
        TriagedFinding(
            finding_id=row["finding_id"],
            original_severity=Severity(row["original_severity"]),
            adjusted_severity=Severity(row["adjusted_severity"]),
            exploitability_score=row["exploitability_score"],
            business_priority=row["business_priority"],
            triage_rationale=row["triage_rationale"],
            recommended_timeline=row["recommended_timeline"],
        )
        for row in conn.execute(
            "SELECT * FROM triaged_findings WHERE session_id = ?", (session_id,)
        )
    ]
    return enrichments, chains, triaged
