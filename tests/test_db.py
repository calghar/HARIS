"""Tests for the SQLite storage layer."""

from __future__ import annotations

from src.db.store import ScanStore
from src.models import (
    Confidence,
    Effort,
    Finding,
    RemediationStep,
    RiskPosture,
    ScanSession,
    Severity,
    Target,
)


def _make_session() -> ScanSession:
    """Create a realistic test session."""
    target = Target(base_url="https://example.com")
    findings = [
        Finding(
            title="SQL Injection in search",
            description="The search parameter is vulnerable.",
            severity=Severity.CRITICAL,
            confidence=Confidence.CONFIRMED,
            url="https://example.com/search?q=test",
            parameter="q",
            remediation="Use parameterised queries.",
            scanner="wapiti",
            tags=["sql_injection"],
            finding_id="f001",
            owasp_category="A05:2025 - Injection",
            cwe_id="CWE-89",
            evidence="Error: SQL syntax",
        ),
        Finding(
            title="Missing HSTS header",
            description="The response lacks HSTS.",
            severity=Severity.MEDIUM,
            confidence=Confidence.CONFIRMED,
            url="https://example.com",
            remediation="Add Strict-Transport-Security header.",
            scanner="header_checks",
            tags=["missing_hsts"],
            finding_id="f002",
            owasp_category="A04:2025 - Cryptographic Failures",
        ),
    ]
    remediation_steps = [
        RemediationStep(
            title="Fix SQL Injection",
            description="Use parameterised queries everywhere.",
            effort=Effort.MODERATE,
            impact=Severity.CRITICAL,
            finding_count=1,
            category="A05:2025 - Injection",
        ),
        RemediationStep(
            title="Add security headers",
            description="Deploy missing security headers.",
            effort=Effort.QUICK_WIN,
            impact=Severity.MEDIUM,
            finding_count=1,
            category="A04:2025 - Cryptographic Failures",
        ),
    ]
    return ScanSession(
        session_id="test-db-001",
        target=target,
        started_at="2025-02-22T14:30:00+00:00",
        finished_at="2025-02-22T14:35:00+00:00",
        profile_name="full",
        profile_intro="A comprehensive audit.",
        scanners_used=["wapiti", "header_checks"],
        all_findings=findings,
        remediation_steps=remediation_steps,
        risk_posture=RiskPosture.POOR,
        risk_posture_text="Multiple significant vulnerabilities found.",
        errors=["[nikto] Scanner not installed"],
    )


class TestScanStore:
    def test_save_and_load_session(self, tmp_path):
        store = ScanStore(tmp_path / "test.db")
        session = _make_session()

        store.save_session(session)
        loaded = store.load_session("test-db-001")

        assert loaded is not None
        assert loaded.session_id == "test-db-001"
        assert loaded.target.base_url == "https://example.com"
        assert loaded.profile_name == "full"
        assert loaded.started_at == "2025-02-22T14:30:00+00:00"
        assert loaded.finished_at == "2025-02-22T14:35:00+00:00"
        assert loaded.risk_posture == RiskPosture.POOR
        assert loaded.scanners_used == ["wapiti", "header_checks"]
        assert len(loaded.errors) == 1

    def test_findings_roundtrip(self, tmp_path):
        store = ScanStore(tmp_path / "test.db")
        session = _make_session()
        store.save_session(session)

        loaded = store.load_session("test-db-001")
        assert loaded is not None
        assert len(loaded.all_findings) == 2

        f1 = loaded.all_findings[0]
        assert f1.finding_id == "f001"
        assert f1.title == "SQL Injection in search"
        assert f1.severity == Severity.CRITICAL
        assert f1.confidence == Confidence.CONFIRMED
        assert f1.owasp_category == "A05:2025 - Injection"
        assert f1.cwe_id == "CWE-89"
        assert f1.parameter == "q"
        assert f1.scanner == "wapiti"
        assert "sql_injection" in f1.tags

    def test_remediation_roundtrip(self, tmp_path):
        store = ScanStore(tmp_path / "test.db")
        session = _make_session()
        store.save_session(session)

        loaded = store.load_session("test-db-001")
        assert loaded is not None
        assert len(loaded.remediation_steps) == 2

        step = loaded.remediation_steps[0]
        assert step.title == "Fix SQL Injection"
        assert step.effort == Effort.MODERATE
        assert step.impact == Severity.CRITICAL
        assert step.finding_count == 1

    def test_list_sessions(self, tmp_path):
        store = ScanStore(tmp_path / "test.db")
        session = _make_session()
        store.save_session(session)

        sessions = store.list_sessions()
        assert len(sessions) == 1
        assert sessions[0]["session_id"] == "test-db-001"
        assert sessions[0]["target_url"] == "https://example.com"
        assert sessions[0]["finding_count"] == 2
        assert sessions[0]["risk_posture"] == "poor"

    def test_session_exists(self, tmp_path):
        store = ScanStore(tmp_path / "test.db")
        assert not store.session_exists("test-db-001")

        store.save_session(_make_session())
        assert store.session_exists("test-db-001")

    def test_delete_session(self, tmp_path):
        store = ScanStore(tmp_path / "test.db")
        store.save_session(_make_session())

        assert store.delete_session("test-db-001")
        assert not store.session_exists("test-db-001")
        assert store.load_session("test-db-001") is None

    def test_delete_nonexistent_session(self, tmp_path):
        store = ScanStore(tmp_path / "test.db")
        assert not store.delete_session("nonexistent")

    def test_load_nonexistent_session(self, tmp_path):
        store = ScanStore(tmp_path / "test.db")
        assert store.load_session("nonexistent") is None

    def test_get_findings_no_filter(self, tmp_path):
        store = ScanStore(tmp_path / "test.db")
        store.save_session(_make_session())

        findings = store.get_findings("test-db-001")
        assert len(findings) == 2

    def test_get_findings_by_severity(self, tmp_path):
        store = ScanStore(tmp_path / "test.db")
        store.save_session(_make_session())

        findings = store.get_findings("test-db-001", severity="critical")
        assert len(findings) == 1
        assert findings[0]["title"] == "SQL Injection in search"

    def test_get_findings_by_owasp(self, tmp_path):
        store = ScanStore(tmp_path / "test.db")
        store.save_session(_make_session())

        findings = store.get_findings(
            "test-db-001", owasp_category="Injection"
        )
        assert len(findings) == 1
        assert findings[0]["finding_id"] == "f001"

    def test_upsert_replaces_session(self, tmp_path):
        store = ScanStore(tmp_path / "test.db")
        session = _make_session()
        store.save_session(session)

        # Modify and re-save
        session.all_findings = session.all_findings[:1]
        store.save_session(session)

        loaded = store.load_session("test-db-001")
        assert loaded is not None
        assert len(loaded.all_findings) == 1

    def test_empty_session(self, tmp_path):
        store = ScanStore(tmp_path / "test.db")
        target = Target(base_url="https://empty.example.com")
        session = ScanSession(
            session_id="empty-001",
            target=target,
        )
        store.save_session(session)

        loaded = store.load_session("empty-001")
        assert loaded is not None
        assert len(loaded.all_findings) == 0
        assert len(loaded.remediation_steps) == 0
        assert loaded.risk_posture == RiskPosture.EXCELLENT

    def test_multiple_sessions(self, tmp_path):
        store = ScanStore(tmp_path / "test.db")

        for i in range(3):
            target = Target(base_url=f"https://site{i}.example.com")
            session = ScanSession(
                session_id=f"multi-{i:03d}",
                target=target,
                started_at=f"2025-02-22T{10+i}:00:00+00:00",
            )
            store.save_session(session)

        sessions = store.list_sessions()
        assert len(sessions) == 3

    def test_enrichment_roundtrip(self, tmp_path):
        from src.models.enrichment import (
            AttackChain,
            EnrichedFinding,
            TriagedFinding,
        )

        store = ScanStore(tmp_path / "test.db")
        session = _make_session()

        session.llm_enrichments = {
            "f001": EnrichedFinding(
                finding_id="f001",
                attack_narrative="Attacker injects SQL via search.",
                business_impact_assessment="Full DB compromise.",
                exploitation_complexity="low",
                false_positive_likelihood="very_low",
                related_cwes=["CWE-89", "CWE-564"],
                attack_chain_position="entry_point",
                variant_suggestions=["blind SQLi", "time-based SQLi"],
            ),
        }
        session.attack_chains = [
            AttackChain(
                chain_id="chain-001",
                name="DB Exfiltration Chain",
                description="SQLi leads to data theft.",
                finding_ids=["f001", "f002"],
                total_impact="critical",
                likelihood="high",
            ),
        ]
        session.triaged_findings = [
            TriagedFinding(
                finding_id="f001",
                original_severity=Severity.CRITICAL,
                adjusted_severity=Severity.CRITICAL,
                exploitability_score=9,
                business_priority=10,
                triage_rationale="Directly exploitable.",
                recommended_timeline="immediate",
            ),
        ]

        store.save_session(session)
        loaded = store.load_session("test-db-001")

        assert loaded is not None
        assert "f001" in loaded.llm_enrichments
        enr = loaded.llm_enrichments["f001"]
        assert enr.attack_narrative == "Attacker injects SQL via search."
        assert enr.exploitation_complexity == "low"
        assert "CWE-89" in enr.related_cwes

        assert len(loaded.attack_chains) == 1
        assert loaded.attack_chains[0].name == "DB Exfiltration Chain"
        assert loaded.attack_chains[0].finding_ids == ["f001", "f002"]

        assert len(loaded.triaged_findings) == 1
        tf = loaded.triaged_findings[0]
        assert tf.exploitability_score == 9
        assert tf.business_priority == 10
        assert tf.recommended_timeline == "immediate"

    def test_false_positive_and_executive_priorities_persist(self, tmp_path):
        store = ScanStore(tmp_path / "test.db")
        session = _make_session()

        session.false_positive_assessments = [
            {"finding_id": "f002", "assessment": "likely_fp", "reason": "Standard header"},
        ]
        session.executive_priorities = "Fix SQL injection immediately."

        store.save_session(session)
        loaded = store.load_session("test-db-001")

        assert loaded is not None
        assert len(loaded.false_positive_assessments) == 1
        assert loaded.false_positive_assessments[0]["finding_id"] == "f002"
        assert loaded.executive_priorities == "Fix SQL injection immediately."

    def test_empty_enrichment_roundtrip(self, tmp_path):
        """Sessions without enrichment data should load cleanly."""
        store = ScanStore(tmp_path / "test.db")
        session = _make_session()
        store.save_session(session)

        loaded = store.load_session("test-db-001")
        assert loaded is not None
        assert loaded.llm_enrichments == {}
        assert loaded.attack_chains == []
        assert loaded.triaged_findings == []
        assert loaded.false_positive_assessments == []
        assert loaded.executive_priorities == ""
