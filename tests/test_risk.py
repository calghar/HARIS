import pytest

from haris.core.risk import (
    assess_risk_posture,
    get_business_impact,
    risk_posture_summary,
)
from haris.models import (
    CorrelatedFinding,
    Finding,
    OwaspCategory,
    RiskPosture,
    Severity,
    Suppression,
    VerificationTier,
)


def correlated(severity: Severity, score: float, tier: VerificationTier | None = None):
    finding = Finding(
        title="x", description="", severity=severity, confidence_score=score
    )
    if tier is not None:
        finding.verification.advance(tier)
    return CorrelatedFinding(canonical=finding, consensus_score=score)


class TestAssessRiskPosture:
    def test_no_findings_is_excellent(self):
        assert assess_risk_posture([]) == RiskPosture.EXCELLENT

    @pytest.mark.parametrize(
        ("severities", "posture"),
        [
            ([Severity.LOW], RiskPosture.GOOD),
            ([Severity.INFO], RiskPosture.EXCELLENT),
            ([Severity.CRITICAL], RiskPosture.POOR),
            ([Severity.CRITICAL] * 2, RiskPosture.CRITICAL),
            ([Severity.MEDIUM] * 4, RiskPosture.MODERATE),
        ],
    )
    def test_thresholds_at_full_confidence(self, severities, posture):
        findings = [correlated(s, 1.0) for s in severities]
        assert assess_risk_posture(findings) == posture

    @pytest.mark.parametrize(
        ("tier", "score", "posture"),
        [
            (VerificationTier.UNVERIFIED, 0.5, RiskPosture.GOOD),
            (VerificationTier.REPLAY_VERIFIED, 0.9, RiskPosture.GOOD),
            (VerificationTier.EXPLOIT_VALIDATED, 1.0, RiskPosture.MODERATE),
            (VerificationTier.REFUTED, 0.0, RiskPosture.EXCELLENT),
        ],
    )
    def test_risk_by_tier(self, tier, score, posture):
        """Scenario: Risk by tier."""
        assert assess_risk_posture([correlated(Severity.HIGH, score, tier)]) == posture

    def test_refuted_excluded_even_with_nonzero_score(self):
        finding = correlated(Severity.CRITICAL, 1.0, VerificationTier.REFUTED)
        assert assess_risk_posture([finding]) == RiskPosture.EXCELLENT

    def test_suppressed_excluded(self):
        finding = correlated(Severity.CRITICAL, 1.0)
        finding.canonical.suppression = Suppression(
            reason="accepted", author="a@example.com", expires="2027-01-01"
        )
        assert assess_risk_posture([finding]) == RiskPosture.EXCELLENT

    def test_unknown_when_no_scanner_completed(self):
        """Scenario: All scanners failed (posture half)."""
        posture = assess_risk_posture([], scanner_completed=False)
        assert posture == RiskPosture.UNKNOWN


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
