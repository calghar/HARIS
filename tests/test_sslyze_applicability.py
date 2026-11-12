import json
from pathlib import Path
from typing import Any

import pytest

from haris.core.context_extract import extract_context
from haris.core.engine import ScanEngine
from haris.models import ScannerResult, ScanSession, ScanState, Target
from haris.models.scan_context import ScanContext
from haris.reporting.json_report import JSONReporter
from haris.reporting.markdown_report import MarkdownReporter
from haris.scanners.base import ToolRun
from haris.scanners.nmap_scanner import NmapScanner
from haris.scanners.sslyze_scanner import SSLyzeScanner
from tests.test_engine_pipeline import Probe, finding

NOTE = "no TLS endpoint"
PUBLIC = "93.184.216.34"
MODERN_TLS = (
    Path(__file__).parent / "fixtures" / "scanners" / "sslyze" / "modern_tls.json"
).read_text()
NMAP_XML = Path(__file__).parent / "fixtures" / "scanners" / "nmap" / "scan.xml"


def public_host(_host: str, _port: int) -> list[str]:
    return [PUBLIC]


class RecordingSSLyze(SSLyzeScanner):
    """Real adapter with the process boundary replaced; records every start."""

    def __init__(self) -> None:
        super().__init__()
        self.started: list[list[str]] = []

    def _check_tool_available(self, binary: str) -> bool:
        return True

    def _run_to_file(self, cmd: list[str], output_file: Path, timeout: int) -> ToolRun:
        self.started.append(cmd)
        return ToolRun(0, "", MODERN_TLS, False)


def nmap_port(port: str, **raw: str) -> Probe:
    port_finding = finding(
        f"Open port {port}/tcp", f"host:{port}", "nmap", raw_data={"port": port, **raw}
    )
    return Probe("nmap", findings=[port_finding])


def run(url: str, *scanners: Any) -> ScanSession:
    engine = ScanEngine(scanners=list(scanners), parallel=1, resolver=public_host)
    return engine.run(Target(base_url=url))


def test_plain_http_without_tls_port_skips_sslyze_and_scan_completes():
    sslyze = RecordingSSLyze()
    session = run("http://host:8080", nmap_port("8080", service="http"), sslyze)

    assert session.scanner_status == {"nmap": "completed", "sslyze": "skipped"}
    assert session.scanner_notes == {"sslyze": NOTE}
    assert session.scan_state is ScanState.COMPLETED
    assert sslyze.started == []
    assert session.scanner_results[-1].errors == []


@pytest.fixture
def only_sslyze_skipped() -> tuple[ScanSession, RecordingSSLyze]:
    sslyze = RecordingSSLyze()
    return run("http://host:8080", sslyze), sslyze


def test_every_scanner_skipped_completes_and_reports_the_note(only_sslyze_skipped):
    session, sslyze = only_sslyze_skipped

    assert session.scan_state is ScanState.COMPLETED
    assert sslyze.started == []
    data = json.loads(JSONReporter().generate(session))
    assert data["scanner_notes"] == {"sslyze": NOTE}
    assert NOTE in MarkdownReporter().generate(session)


def test_https_target_runs_sslyze_against_its_own_port():
    sslyze = RecordingSSLyze()
    session = run("https://host", sslyze)

    assert [cmd[-2:] for cmd in sslyze.started] == [["--", f"host:443{{{PUBLIC}}}"]]
    assert session.scanner_status == {"sslyze": "completed"}
    assert session.scanner_notes == {}


def test_http_target_with_nmap_ssl_tunnel_port_runs_sslyze():
    sslyze = RecordingSSLyze()
    session = run(
        "http://host:8080",
        nmap_port("18443", service="http", tunnel="ssl"),
        sslyze,
    )

    assert [cmd[-2:] for cmd in sslyze.started] == [["--", f"host:8080{{{PUBLIC}}}"]]
    assert session.scanner_status["sslyze"] == "completed"


def test_http_target_without_context_counts_as_no_tls_port():
    sslyze = RecordingSSLyze()
    result = sslyze.scan(Target(base_url="http://host:8080"))

    assert result.metadata == {"status": "skipped", "note": NOTE}
    assert result.errors == []
    assert sslyze.started == []


@pytest.mark.parametrize(
    ("raw", "is_tls"),
    [
        ({"port": "18443", "service": "http", "tunnel": "ssl"}, True),
        ({"port": "443", "service": "https", "tunnel": ""}, True),
        ({"port": "8443", "service": "https-alt"}, True),
        ({"port": "8443", "service": "ssl/http"}, True),
        ({"port": "80", "service": "http", "tunnel": ""}, False),
        ({"port": "8080", "service": "http-proxy"}, False),
        ({"port": "9000"}, False),
    ],
)
def test_nmap_port_is_recorded_as_tls_only_for_tls_services(raw, is_tls):
    context = ScanContext()
    result = ScannerResult(
        scanner_name="nmap",
        findings=[finding("Open port", f"host:{raw['port']}", "nmap", raw_data=raw)],
    )
    extract_context("nmap", result, context)

    assert context.open_ports == [raw["port"]]
    assert context.tls_ports == ([raw["port"]] if is_tls else [])


def test_nmap_xml_tunnel_attribute_reaches_the_context():
    findings = NmapScanner().parse_results(NMAP_XML.read_text())
    context = ScanContext()
    extract_context(
        "nmap", ScannerResult(scanner_name="nmap", findings=findings), context
    )

    assert context.tls_ports == ["18443"]
