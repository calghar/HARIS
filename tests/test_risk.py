from src.core.risk import assess_risk_posture, get_business_impact, risk_posture_summary
from src.models import Finding, OwaspCategory, RiskPosture, Severity


class TestAssessRiskPosture:
    def test_no_findings_is_excellent(self):
        assert assess_risk_posture([]) == RiskPosture.EXCELLENT

    def test_one_low_is_good(self):
        findings = [Finding(title="", description="", severity=Severity.LOW)]
        assert assess_risk_posture(findings) == RiskPosture.GOOD

    def test_critical_finding_pushes_to_poor(self):
        findings = [Finding(title="", description="", severity=Severity.CRITICAL)]
        assert assess_risk_posture(findings) == RiskPosture.POOR

    def test_two_criticals_is_critical_posture(self):
        findings = [
            Finding(title="", description="", severity=Severity.CRITICAL),
            Finding(title="", description="", severity=Severity.CRITICAL),
        ]
        assert assess_risk_posture(findings) == RiskPosture.CRITICAL

    def test_moderate_range(self):
        findings = [
            Finding(title="", description="", severity=Severity.MEDIUM),
            Finding(title="", description="", severity=Severity.MEDIUM),
            Finding(title="", description="", severity=Severity.MEDIUM),
            Finding(title="", description="", severity=Severity.MEDIUM),
        ]
        assert assess_risk_posture(findings) == RiskPosture.MODERATE


class TestGetBusinessImpact:
    def test_mapped_category(self):
        f = Finding(
            title="SQLi",
            description="",
            severity=Severity.CRITICAL,
            owasp_category=OwaspCategory.A05_INJECTION.value,
        )
        impact = get_business_impact(f)
        headline = impact.headline.lower()
        assert "execute" in headline or "command" in headline
        assert impact.worst_case != ""

    def test_unmapped_category_returns_fallback(self):
        f = Finding(
            title="Something",
            description="",
            severity=Severity.LOW,
            owasp_category="Unknown Category",
        )
        impact = get_business_impact(f)
        assert impact.headline != ""


class TestRiskPostureSummary:
    def test_all_postures_have_summaries(self):
        for posture in RiskPosture:
            text = risk_posture_summary(posture)
            assert len(text) > 20
