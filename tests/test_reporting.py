import json
import tempfile
from pathlib import Path
from types import SimpleNamespace

from haris.cli import _write_reports
from haris.diff import LoadedReport
from haris.models import Confidence, Finding, ScanSession, Severity, Target
from haris.reporting.json_report import JSONReporter
from haris.reporting.markdown_report import MarkdownReporter
from haris.web.scan_runtime import write_reports


def _make_session() -> ScanSession:
    """Create a test session with sample findings."""
    target = Target(base_url="https://example.com")
    session = ScanSession(
        session_id="test-001",
        target=target,
        started_at="2025-01-15T10:00:00+00:00",
        finished_at="2025-01-15T10:05:00+00:00",
        scanners_used=["header_checks", "tls_checks"],
        all_findings=[
            Finding(
                title="Missing HSTS header",
                description="No Strict-Transport-Security header found.",
                severity=Severity.MEDIUM,
                confidence=Confidence.CONFIRMED,
                url="https://example.com",
                owasp_category="A04:2025 - Cryptographic Failures",
                remediation="Add the HSTS header.",
                scanner="header_checks",
            ),
            Finding(
                title="Reflected XSS in search",
                description="XSS via the q parameter.",
                severity=Severity.HIGH,
                confidence=Confidence.FIRM,
                url="https://example.com/search",
                parameter="q",
                method="GET",
                owasp_category="A05:2025 - Injection",
                evidence="<script>alert(1)</script>",
                request_example="curl 'https://example.com/search?q=<script>alert(1)</script>'",
                remediation="Sanitise user input and encode output.",
                scanner="wapiti",
            ),
        ],
    )
    return session


class TestJSONReporter:
    def test_generates_valid_json(self):
        session = _make_session()
        reporter = JSONReporter()
        output = reporter.generate(session)

        data = json.loads(output)
        assert data["meta"]["session_id"] == "test-001"
        assert len(data["findings"]) == 2

    def test_findings_structure(self):
        session = _make_session()
        reporter = JSONReporter()
        output = reporter.generate(session)

        data = json.loads(output)
        finding = data["findings"][0]
        assert "title" in finding
        assert "severity" in finding
        assert "owasp_category" in finding

    def test_includes_risk_posture(self):
        session = _make_session()
        reporter = JSONReporter()
        output = reporter.generate(session)

        data = json.loads(output)
        assert "risk_posture" in data
        assert "level" in data["risk_posture"]

    def test_includes_remediation(self):
        session = _make_session()
        reporter = JSONReporter()
        output = reporter.generate(session)

        data = json.loads(output)
        assert "remediation" in data

    def test_write_to_file(self):
        session = _make_session()
        reporter = JSONReporter()

        with tempfile.TemporaryDirectory() as tmpdir:
            path = reporter.write(session, Path(tmpdir) / "report.json")
            assert path.exists()
            data = json.loads(path.read_text())
            assert data["meta"]["target"] == "https://example.com"


class TestMarkdownReporter:
    def test_contains_executive_summary(self):
        session = _make_session()
        reporter = MarkdownReporter()
        output = reporter.generate(session)

        assert "## Executive Summary" in output
        assert "2 finding" in output

    def test_contains_methodology(self):
        session = _make_session()
        reporter = MarkdownReporter()
        output = reporter.generate(session)

        assert "## Methodology" in output
        assert "header_checks" in output

    def test_contains_findings(self):
        session = _make_session()
        reporter = MarkdownReporter()
        output = reporter.generate(session)

        assert "Missing HSTS" in output
        assert "Reflected XSS" in output
        assert "Remediation" in output

    def test_owasp_categories_listed(self):
        session = _make_session()
        reporter = MarkdownReporter()
        output = reporter.generate(session)

        assert "A01:2025" in output
        assert "A05:2025" in output

    def test_empty_findings(self):
        session = _make_session()
        session.all_findings = []
        reporter = MarkdownReporter()
        output = reporter.generate(session)

        assert "No findings" in output


def test_cli_and_web_write_the_same_report_filename(tmp_path: Path) -> None:
    session = _make_session()
    session.session_id = "sess-1"
    session.target = Target(base_url="https://app.example.com:8443/admin")
    cli_dir = tmp_path / "cli"
    web_dir = tmp_path / "web"
    _write_reports(
        session,
        SimpleNamespace(output_dir=str(cli_dir), report_formats=["json"]),
        LoadedReport(),
    )
    write_reports(
        SimpleNamespace(settings=SimpleNamespace(reports_dir=web_dir)),
        session,
        ["json"],
    )
    names = ["report_app.example.com_sess-1.json"]
    assert sorted(p.name for p in cli_dir.iterdir()) == names
    assert sorted(p.name for p in web_dir.iterdir()) == names
