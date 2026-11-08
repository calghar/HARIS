import pytest

from haris.core.confidence import consensus, finalise, rescore
from haris.core.correlator import FindingCorrelator
from haris.models import (
    Confidence,
    Finding,
    LLMAssessment,
    Severity,
    VerificationTier,
)

BASE = "https://example.com"


def make(**kwargs: object) -> Finding:
    fields: dict[str, object] = {
        "title": "Reflected XSS",
        "description": "",
        "severity": Severity.HIGH,
        "vuln_class": "xss_reflected",
        "parameter": "q",
        "url": "https://example.com/search?q=y",
        "scanner": "nuclei",
    }
    fields.update(kwargs)
    return Finding.model_validate(fields)


def test_two_scanners_with_different_titles_merge():
    """Scenario: Two scanners with different titles merge."""
    wapiti = make(
        title="Cross Site Scripting", url="/search?q=x", scanner="wapiti", vuln_class=""
    )
    nuclei = make(title="Reflected XSS", vuln_class="")
    correlated = FindingCorrelator().correlate([wapiti, nuclei], BASE)

    assert len(correlated) == 1
    assert {s for s, _ in correlated[0].sources} == {"wapiti", "nuclei"}
    assert correlated[0].canonical.fingerprint
    assert (
        correlated[0].canonical.finding_id == correlated[0].canonical.fingerprint[:16]
    )


def test_inputs_are_not_mutated():
    """Scenario: Inputs are not mutated."""
    a = make(scanner="wapiti", confidence=Confidence.TENTATIVE)
    b = make(scanner="nuclei", confidence=Confidence.TENTATIVE)
    before = [f.model_dump() for f in (a, b)]

    correlated = FindingCorrelator().correlate([a, b], BASE)

    assert a.confidence == b.confidence == Confidence.TENTATIVE
    assert [f.model_dump() for f in (a, b)] == before
    assert correlated[0].canonical is not a
    assert correlated[0].canonical is not b


def test_unmapped_findings_from_different_scanners_stay_separate():
    """Scenario: Unmapped findings from different scanners stay separate."""
    nikto = make(title="Interesting header", scanner="nikto", vuln_class="")
    nuclei = make(title="Interesting header", scanner="nuclei", vuln_class="")
    correlated = FindingCorrelator().correlate([nikto, nuclei], BASE)

    assert {c.canonical.vuln_class for c in correlated} == {
        "unclassified:nikto:interesting-header",
        "unclassified:nuclei:interesting-header",
    }


def test_empty_input():
    assert FindingCorrelator().correlate([], BASE) == []


def test_canonical_keeps_highest_severity_and_best_tier():
    low = make(scanner="wapiti", severity=Severity.LOW)
    high = make(scanner="nuclei", severity=Severity.CRITICAL)
    refuted = make(scanner="nikto", severity=Severity.MEDIUM)
    refuted.verification.advance(VerificationTier.REFUTED)
    [merged] = FindingCorrelator().correlate([refuted, low, high], BASE)

    assert merged.canonical.severity == Severity.CRITICAL
    assert merged.canonical.scanner == "nuclei"
    assert merged.canonical.verification.tier == VerificationTier.UNVERIFIED


@pytest.mark.parametrize(
    ("priors", "tier", "score", "enum"),
    [
        ([0.5], VerificationTier.UNVERIFIED, 0.5, Confidence.TENTATIVE),
        ([0.5, 0.5], VerificationTier.UNVERIFIED, 0.75, Confidence.FIRM),
        ([0.8, 0.9, 0.9], VerificationTier.UNVERIFIED, 0.95, Confidence.CONFIRMED),
        ([0.5], VerificationTier.REPLAY_VERIFIED, 0.9, Confidence.CONFIRMED),
        ([0.5], VerificationTier.EXPLOIT_VALIDATED, 1.0, Confidence.CONFIRMED),
        ([0.8, 0.9], VerificationTier.REFUTED, 0.0, Confidence.TENTATIVE),
    ],
)
def test_consensus_and_tier_floors(priors, tier, score, enum):
    """Scenario: Consensus and tier floors."""
    findings = [
        make(scanner=f"scanner{i}", confidence_score=p) for i, p in enumerate(priors)
    ]
    for f in findings:
        f.verification.advance(tier)
    [merged] = FindingCorrelator().correlate(findings, BASE)

    assert merged.canonical.confidence_score == pytest.approx(score)
    assert merged.canonical.confidence == enum


def test_consensus_uses_highest_prior_per_scanner():
    same_scanner = [make(confidence_score=0.5), make(confidence_score=0.5)]
    [merged] = FindingCorrelator().correlate(same_scanner, BASE)
    assert merged.canonical.confidence_score == pytest.approx(0.5)
    assert consensus([0.5, 0.5]) == pytest.approx(0.75)


def test_llm_verdict_adjusts_score_but_not_tier():
    """Scenario: LLM verdict adjusts score but not tier."""
    [merged] = FindingCorrelator().correlate([make(confidence_score=0.5)], BASE)
    merged.canonical.verification.llm = LLMAssessment(
        verdict="likely_fp", confidence=1.0
    )
    rescore(merged)

    assert merged.canonical.confidence_score == pytest.approx(0.2)
    assert merged.canonical.verification.tier == VerificationTier.UNVERIFIED


@pytest.mark.parametrize(
    ("score", "verdict", "llm_conf", "status", "tier", "expected"),
    [
        (0.5, "confirmed", 1.0, "ok", VerificationTier.UNVERIFIED, 0.65),
        (0.8, "confirmed", 1.0, "ok", VerificationTier.UNVERIFIED, 0.89),
        (0.95, "confirmed", 1.0, "ok", VerificationTier.UNVERIFIED, 0.95),
        (0.1, "likely_fp", 1.0, "ok", VerificationTier.UNVERIFIED, 0.05),
        (0.5, "likely_fp", 1.0, "invalid", VerificationTier.UNVERIFIED, 0.5),
        (0.5, "likely_fp", 1.0, "ok", VerificationTier.REPLAY_VERIFIED, 0.9),
    ],
)
def test_llm_adjustment_bounds_and_floor_precedence(
    score, verdict, llm_conf, status, tier, expected
):
    llm = LLMAssessment(verdict=verdict, confidence=llm_conf, status=status)
    assert finalise(score, tier, llm) == pytest.approx(expected)
