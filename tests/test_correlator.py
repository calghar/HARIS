from src.core.correlator import FindingCorrelator
from src.models import Confidence, Finding, Severity


class TestFindingCorrelator:
    def test_deduplicates_same_finding_from_two_scanners(self):
        f1 = Finding(
            title="XSS in search",
            description="Reflected XSS",
            severity=Severity.HIGH,
            confidence=Confidence.FIRM,
            url="https://example.com/search",
            parameter="q",
            method="GET",
            scanner="wapiti",
            tags=["xss"],
        )
        f2 = Finding(
            title="XSS in search",
            description="Cross-site scripting",
            severity=Severity.HIGH,
            confidence=Confidence.TENTATIVE,
            url="https://example.com/search",
            parameter="q",
            method="GET",
            scanner="nuclei",
            tags=["xss"],
        )

        correlator = FindingCorrelator()
        correlated = correlator.correlate([f1, f2])

        assert len(correlated) == 1
        assert correlated[0].multi_confirmed
        assert correlated[0].confirmed_by == 2
        # Should pick the higher-confidence finding as canonical
        assert correlated[0].canonical.confidence == Confidence.CONFIRMED

    def test_different_findings_not_merged(self):
        f1 = Finding(
            title="Missing HSTS",
            description="",
            severity=Severity.MEDIUM,
            url="https://example.com/",
            scanner="header_checks",
            tags=["missing_hsts"],
        )
        f2 = Finding(
            title="SQL Injection",
            description="",
            severity=Severity.CRITICAL,
            url="https://example.com/login",
            parameter="username",
            method="POST",
            scanner="wapiti",
            tags=["sql_injection"],
        )

        correlator = FindingCorrelator()
        correlated = correlator.correlate([f1, f2])

        assert len(correlated) == 2

    def test_empty_input(self):
        correlator = FindingCorrelator()
        assert correlator.correlate([]) == []

    def test_single_finding(self):
        f = Finding(
            title="Test",
            description="",
            severity=Severity.LOW,
            scanner="test",
        )
        correlator = FindingCorrelator()
        correlated = correlator.correlate([f])
        assert len(correlated) == 1
        assert not correlated[0].multi_confirmed
