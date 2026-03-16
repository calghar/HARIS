"""Tests for the ScanEngine orchestration."""

from src.core.engine import ScanEngine
from src.core.scanner import BaseScanner
from src.models import Confidence, Finding, ScannerResult, ScanSession, Severity, Target


class MockScanner(BaseScanner):
    """A mock scanner for testing the engine."""

    name = "mock"
    version = "0.0.1"
    description = "Mock scanner for tests"

    def __init__(self, findings=None, errors=None):
        super().__init__()
        self._findings = findings or []
        self._errors = errors or []

    def scan(self, target):
        return ScannerResult(
            scanner_name=self.name,
            raw_output="mock raw output",
            findings=self._findings,
            errors=self._errors,
        )

    def parse_results(self, raw_output):
        return self._findings


class FailingScanner(BaseScanner):
    """A scanner that raises an exception."""

    name = "failing"
    version = "0.0.1"

    def scan(self, target):
        raise RuntimeError("Scanner exploded")

    def parse_results(self, raw_output):
        return []


class TestScanEngine:
    def test_empty_scan(self):
        engine = ScanEngine(scanners=[])
        target = Target(base_url="https://example.com")
        session = engine.run(target)

        assert isinstance(session, ScanSession)
        assert session.all_findings == []
        assert session.scanners_used == []

    def test_scan_with_findings(self):
        findings = [
            Finding(
                title="Test Finding",
                description="A test",
                severity=Severity.HIGH,
                confidence=Confidence.CONFIRMED,
                url="https://example.com/vuln",
                scanner="mock",
                tags=["xss"],
            )
        ]
        scanner = MockScanner(findings=findings)
        engine = ScanEngine(scanners=[scanner])
        target = Target(base_url="https://example.com")
        session = engine.run(target)

        assert len(session.all_findings) == 1
        assert session.all_findings[0].title == "Test Finding"
        assert "mock" in session.scanners_used

    def test_scan_deduplicates_findings(self):
        dup = Finding(
            title="Duplicate",
            description="Same finding",
            severity=Severity.MEDIUM,
            url="https://example.com/page",
            parameter="q",
        )
        # Two scanners returning the same finding
        s1 = MockScanner(findings=[dup])
        s2 = MockScanner(findings=[dup])
        engine = ScanEngine(scanners=[s1, s2])
        target = Target(base_url="https://example.com")
        session = engine.run(target)

        assert len(session.all_findings) == 1

    def test_scanner_error_captured(self):
        scanner = MockScanner(errors=["something went wrong"])
        engine = ScanEngine(scanners=[scanner])
        target = Target(base_url="https://example.com")
        session = engine.run(target)

        assert len(session.errors) == 1
        assert "something went wrong" in session.errors[0]

    def test_scanner_exception_captured(self):
        scanner = FailingScanner()
        engine = ScanEngine(scanners=[scanner])
        target = Target(base_url="https://example.com")
        session = engine.run(target)

        assert len(session.errors) == 1
        assert "failed" in session.errors[0].lower()

    def test_findings_sorted_by_severity(self):
        findings = [
            Finding(title="Low", description="", severity=Severity.LOW),
            Finding(title="Critical", description="", severity=Severity.CRITICAL),
            Finding(title="Medium", description="", severity=Severity.MEDIUM),
        ]
        scanner = MockScanner(findings=findings)
        engine = ScanEngine(scanners=[scanner])
        target = Target(base_url="https://example.com")
        session = engine.run(target)

        severities = [f.severity for f in session.all_findings]
        assert severities == [Severity.CRITICAL, Severity.MEDIUM, Severity.LOW]

    def test_owasp_auto_mapping(self):
        finding = Finding(
            title="Test",
            description="",
            severity=Severity.HIGH,
            tags=["sql_injection"],
        )
        scanner = MockScanner(findings=[finding])
        engine = ScanEngine(scanners=[scanner])
        target = Target(base_url="https://example.com")
        session = engine.run(target)

        assert session.all_findings[0].owasp_category != ""
        assert "Injection" in session.all_findings[0].owasp_category

    def test_session_summary(self):
        findings = [
            Finding(title="A", description="", severity=Severity.HIGH),
            Finding(title="B", description="", severity=Severity.LOW),
        ]
        scanner = MockScanner(findings=findings)
        engine = ScanEngine(scanners=[scanner], session_id="test-session")
        target = Target(base_url="https://example.com")
        session = engine.run(target)

        summary = session.summary()
        assert summary["session_id"] == "test-session"
        assert summary["total_findings"] == 2
        assert summary["by_severity"]["high"] == 1
        assert summary["by_severity"]["low"] == 1
