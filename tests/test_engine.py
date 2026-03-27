from src.core.engine import ScanEngine
from src.core.scanner import BaseScanner
from src.models import (
    Confidence,
    Finding,
    ScannerResult,
    ScanSession,
    Severity,
    Target,
)
from src.models.scan_context import ScanContext


class MockScanner(BaseScanner):
    """A mock scanner for testing the engine."""

    name = "mock"
    version = "0.0.1"
    description = "Mock scanner for tests"

    def __init__(self, findings=None, errors=None):
        super().__init__()
        self._findings = findings or []
        self._errors = errors or []

    def scan(self, target, **kwargs):
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

    def scan(self, target, **kwargs):
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


class TestExtractContext:
    def test_extract_from_nmap_findings(self):
        ctx = ScanContext()
        findings = [
            Finding(
                title="Open Port",
                description="Port 443 open",
                severity=Severity.INFO,
                raw_data={
                    "port": 443,
                    "service": "https",
                    "product": "nginx",
                    "version": "1.18.0",
                },
            )
        ]
        result = ScannerResult(
            scanner_name="nmap",
            raw_output="",
            findings=findings,
        )
        ScanEngine._extract_context("nmap", result, ctx)

        assert "443" in ctx.open_ports
        assert "nginx" in ctx.detected_technologies
        assert "https" in ctx.detected_technologies
        assert "nginx/1.18.0" in ctx.detected_technologies

    def test_extract_from_nmap_multiple_ports(self):
        ctx = ScanContext()
        findings = [
            Finding(
                title="Port 80",
                description="",
                severity=Severity.INFO,
                raw_data={"port": 80, "service": "http"},
            ),
            Finding(
                title="Port 443",
                description="",
                severity=Severity.INFO,
                raw_data={"port": 443, "service": "https"},
            ),
        ]
        result = ScannerResult(scanner_name="nmap", raw_output="", findings=findings)
        ScanEngine._extract_context("nmap", result, ctx)

        assert "80" in ctx.open_ports
        assert "443" in ctx.open_ports

    def test_extract_from_nikto_findings(self):
        ctx = ScanContext()
        findings = [
            Finding(
                title="Server Header",
                description="Server: Apache/2.4.41 detected",
                severity=Severity.INFO,
            )
        ]
        result = ScannerResult(scanner_name="nikto", raw_output="", findings=findings)
        ScanEngine._extract_context("nikto", result, ctx)

        assert "apache" in ctx.detected_technologies

    def test_extract_from_nikto_multiple_techs(self):
        ctx = ScanContext()
        findings = [
            Finding(
                title="Tech 1",
                description="nginx server version 1.18.0",
                severity=Severity.INFO,
            ),
            Finding(
                title="Tech 2",
                description="PHP/7.4 detected in headers",
                severity=Severity.INFO,
            ),
            Finding(
                title="Tech 3",
                description="WordPress installation found at /wp-admin",
                severity=Severity.INFO,
            ),
        ]
        result = ScannerResult(scanner_name="nikto", raw_output="", findings=findings)
        ScanEngine._extract_context("nikto", result, ctx)

        assert "nginx" in ctx.detected_technologies
        assert "php" in ctx.detected_technologies
        assert "wordpress" in ctx.detected_technologies

    def test_extract_from_wapiti_findings(self):
        ctx = ScanContext()
        findings = [
            Finding(
                title="XSS",
                description="",
                severity=Severity.HIGH,
                url="https://example.com/search?q=test",
            ),
            Finding(
                title="SQLi",
                description="",
                severity=Severity.HIGH,
                url="https://example.com/admin/login",
            ),
        ]
        result = ScannerResult(scanner_name="wapiti", raw_output="", findings=findings)
        ScanEngine._extract_context("wapiti", result, ctx)

        assert "https://example.com/search?q=test" in ctx.discovered_urls
        assert "https://example.com/admin/login" in ctx.discovered_urls

    def test_extract_from_header_checks(self):
        ctx = ScanContext()
        findings = [
            Finding(
                title="Server Header",
                description="",
                severity=Severity.INFO,
                raw_data={"server": "nginx/1.18.0", "x-powered-by": "PHP/7.4"},
            )
        ]
        result = ScannerResult(
            scanner_name="header_checks", raw_output="", findings=findings
        )
        ScanEngine._extract_context("header_checks", result, ctx)

        assert ctx.server_headers["server"] == "nginx/1.18.0"
        assert ctx.server_headers["x-powered-by"] == "PHP/7.4"
        assert "nginx/1.18.0" in ctx.detected_technologies
        assert "php/7.4" in ctx.detected_technologies

    def test_extract_from_misc_checks(self):
        ctx = ScanContext()
        findings = [
            Finding(
                title="ASP.NET Version",
                description="",
                severity=Severity.INFO,
                raw_data={"x-aspnet-version": "4.0.30319"},
            )
        ]
        result = ScannerResult(
            scanner_name="misc_checks", raw_output="", findings=findings
        )
        ScanEngine._extract_context("misc_checks", result, ctx)

        assert ctx.server_headers["x-aspnet-version"] == "4.0.30319"
        assert "4.0.30319" in ctx.detected_technologies

    def test_extract_filters_non_http_urls(self):
        ctx = ScanContext()
        findings = [
            Finding(
                title="Valid",
                description="",
                severity=Severity.INFO,
                url="https://example.com/page",
            ),
            Finding(
                title="Invalid",
                description="",
                severity=Severity.INFO,
                url="ftp://example.com/file",
            ),
        ]
        result = ScannerResult(scanner_name="wapiti", raw_output="", findings=findings)
        ScanEngine._extract_context("wapiti", result, ctx)

        assert "https://example.com/page" in ctx.discovered_urls
        assert "ftp://example.com/file" not in ctx.discovered_urls

    def test_extract_handles_missing_raw_data(self):
        ctx = ScanContext()
        findings = [
            Finding(
                title="No raw data",
                description="",
                severity=Severity.INFO,
            )
        ]
        result = ScannerResult(scanner_name="nmap", raw_output="", findings=findings)
        ScanEngine._extract_context("nmap", result, ctx)
        # Should not crash

    def test_extract_handles_empty_findings(self):
        ctx = ScanContext()
        result = ScannerResult(scanner_name="nmap", raw_output="", findings=[])
        ScanEngine._extract_context("nmap", result, ctx)
        assert len(ctx.detected_technologies) == 0
        assert len(ctx.discovered_urls) == 0
        assert len(ctx.open_ports) == 0


class TestContextAccumulationAcrossScans:
    def test_context_accumulates_from_multiple_scanners(self):
        engine = ScanEngine(session_id="test-accumulation")
        target = Target(base_url="https://example.com")

        # Mock scanner 1: nmap
        nmap_findings = [
            Finding(
                title="Port scan",
                description="",
                severity=Severity.INFO,
                raw_data={"port": 443, "service": "https", "product": "nginx"},
            )
        ]

        class MockNmap(BaseScanner):
            name = "nmap"

            def scan(self, target, **kwargs):
                return ScannerResult(
                    scanner_name=self.name,
                    raw_output="",
                    findings=nmap_findings,
                )

            def parse_results(self, raw_output):
                return nmap_findings

        # Mock scanner 2: wapiti
        wapiti_findings = [
            Finding(
                title="Crawled page",
                description="",
                severity=Severity.INFO,
                url="https://example.com/admin",
            )
        ]

        class MockWapiti(BaseScanner):
            name = "wapiti"

            def scan(self, target, **kwargs):
                ctx = kwargs.get("context")
                # Verify context has nmap data (accumulated from previous scan)
                if ctx:
                    assert len(ctx.open_ports) > 0
                    assert len(ctx.detected_technologies) > 0
                return ScannerResult(
                    scanner_name=self.name,
                    raw_output="",
                    findings=wapiti_findings,
                )

            def parse_results(self, raw_output):
                return wapiti_findings

        engine.add_scanner(MockNmap())
        engine.add_scanner(MockWapiti())
        session = engine.run(target)

        # Verify both scanners ran and findings were collected
        assert len(session.scanners_used) == 2
        assert "nmap" in session.scanners_used
        assert "wapiti" in session.scanners_used

    def test_context_passed_to_scanners(self):
        received_contexts = []

        class ContextCapturingScanner(BaseScanner):
            name = "context_capture"

            def scan(self, target, **kwargs):
                ctx = kwargs.get("context")
                received_contexts.append(ctx)
                return ScannerResult(scanner_name=self.name, raw_output="", findings=[])

            def parse_results(self, raw_output):
                return []

        engine = ScanEngine(scanners=[ContextCapturingScanner()])
        target = Target(base_url="https://example.com")
        engine.run(target)

        assert len(received_contexts) == 1
        assert isinstance(received_contexts[0], ScanContext)
