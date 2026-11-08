import contextlib
import http.server
import threading
from collections.abc import Callable, Iterator
from typing import Any

import pytest

from haris.core.engine import ScanEngine
from haris.core.exit_codes import exit_code
from haris.core.scanner import BaseScanner
from haris.ignore import IgnoreFile
from haris.models import (
    Finding,
    RiskPosture,
    ScannerResult,
    ScanSession,
    ScanState,
    Scope,
    Severity,
    Target,
)
from haris.models.scan_context import ScanContext
from haris.net import NetworkPolicy, RequestBudgetExceeded

type Action = Callable[[ScanContext], None]


class Probe(BaseScanner):
    """Scanner double that records how the engine called it."""

    version = "0"

    def __init__(
        self,
        name: str,
        *,
        findings: list[Finding] | None = None,
        errors: list[str] | None = None,
        raises: Exception | None = None,
        action: Action | None = None,
    ) -> None:
        super().__init__()
        self.name = name
        self.findings = findings or []
        self.errors = errors or []
        self.raises = raises
        self.action = action
        self.executed = False
        self.rate: float | None = None
        self.context: ScanContext | None = None

    def scan(self, target: Target, context: ScanContext | None = None) -> ScannerResult:
        self.executed = True
        self.context = context
        self.rate = context.tool_rate_rps if context else None
        if self.action and context:
            self.action(context)
        if self.raises:
            raise self.raises
        return ScannerResult(
            scanner_name=self.name,
            findings=list(self.findings),
            errors=list(self.errors),
        )

    def parse_results(self, raw_output: str) -> list[Finding]:
        return []


class _Quiet(http.server.BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        self.send_response(200)
        self.send_header("Content-Length", "2")
        self.end_headers()
        self.wfile.write(b"ok")

    def log_message(self, *_args: object) -> None:
        return None


@pytest.fixture
def local_url() -> Iterator[str]:
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _Quiet)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{server.server_address[1]}"
    server.shutdown()
    server.server_close()


def finding(title: str, url: str, scanner: str, **extra: object) -> Finding:
    fields: dict[str, object] = {
        "title": title,
        "description": "",
        "severity": Severity.HIGH,
        "url": url,
        "scanner": scanner,
        "parameter": "q",
    }
    fields.update(extra)
    return Finding.model_validate(fields)


TARGET = Target(base_url="https://example.com", scope=Scope(rate_limit_rps=10.0))


def test_all_scanners_failed_is_unknown_and_exit_2():
    """Scenario: All scanners failed."""
    engine = ScanEngine(
        scanners=[
            Probe("wapiti", raises=RuntimeError("boom")),
            Probe("nuclei", errors=["timed out"]),
        ]
    )
    session = engine.run(TARGET)

    assert session.scan_state is ScanState.FAILED
    assert session.risk_posture is RiskPosture.UNKNOWN
    assert exit_code(session, None) == 2
    assert any("RuntimeError: boom" in e for e in session.errors)


def test_one_scanner_failing_is_incomplete_and_each_result_is_checkpointed():
    saved: list[tuple[int, int]] = []
    engine = ScanEngine(
        scanners=[
            Probe("wapiti", findings=[finding("XSS", "/a", "wapiti")]),
            Probe("nuclei", errors=["timed out"]),
        ],
        parallel=1,
        checkpoint=lambda s: saved.append((len(s.scanner_results), len(s.errors))),
    )
    session = engine.run(TARGET)

    assert session.scan_state is ScanState.INCOMPLETE
    assert saved == [(1, 0), (2, 1)]
    assert session.scanner_status == {"wapiti": "completed", "nuclei": "failed"}
    assert len(session.all_findings) == 1
    assert exit_code(session, None) == 2


def test_failing_checkpoint_does_not_stop_the_scan():
    def broken(_session: ScanSession) -> None:
        raise OSError("disk full")

    session = ScanEngine(scanners=[Probe("wapiti")], checkpoint=broken).run(TARGET)
    assert session.scan_state is ScanState.COMPLETED


def test_scanners_run_in_parallel():
    barrier = threading.Barrier(2, timeout=5)
    probes = [
        Probe("wapiti", action=lambda _c: barrier.wait()),
        Probe("nuclei", action=lambda _c: barrier.wait()),
    ]
    session = ScanEngine(scanners=probes, parallel=2).run(TARGET)
    assert session.scan_state is ScanState.COMPLETED


def test_cancel_skips_scanners_not_yet_started():
    engine = ScanEngine(scanners=[], parallel=1)
    second = Probe("nuclei")
    engine.add_scanner(Probe("wapiti", action=lambda _c: engine.cancel()))
    engine.add_scanner(second)
    session = engine.run(TARGET)

    assert not second.executed
    assert session.scan_state is ScanState.CANCELLED
    assert exit_code(session, None) == 2


def test_built_in_checks_share_one_client_and_log(local_url):
    """Scenario: Built-in checks share one client."""
    clients: list[Any] = []

    def fetch(path: str) -> Action:
        def run(context: ScanContext) -> None:
            clients.append(context.http)
            context.http.get(f"{local_url}{path}")

        return run

    names = ("header_checks", "misc_checks", "info_disclosure")
    probes = [Probe(n, action=fetch(f"/{n}")) for n in names]
    engine = ScanEngine(
        scanners=probes, network_policy=NetworkPolicy(allow_private=True)
    )
    engine.run(Target(base_url=local_url))

    assert engine.http is not None
    assert {id(c) for c in clients} == {id(engine.http)}
    logged = [e.url for e in engine.http.log.entries()]
    assert sorted(logged) == sorted(f"{local_url}/{n}" for n in names)


def test_preflight_blocks_private_target():
    """Scenario: Pre-flight blocks private target."""
    probes = [Probe("nuclei"), Probe("nikto")]
    session = ScanEngine(scanners=probes).run(Target(base_url="http://192.168.1.10"))

    assert not any(p.executed for p in probes)
    assert session.scan_state is ScanState.FAILED
    assert session.risk_posture is RiskPosture.UNKNOWN
    assert sum("pre-flight" in e for e in session.errors) == 2


def test_allow_private_lets_the_scan_run(local_url):
    probe = Probe("nuclei")
    engine = ScanEngine(
        scanners=[probe], network_policy=NetworkPolicy(allow_private=True)
    )
    session = engine.run(Target(base_url=local_url))
    assert probe.executed
    assert session.scan_state is ScanState.COMPLETED
    assert probe.context is not None
    assert probe.context.target_ip == "127.0.0.1"


def test_rate_is_split_across_concurrent_tools():
    """Scenario: Rate split (nmap is a sequential recon tool and gets the full rate)."""
    nuclei, nikto, nmap = Probe("nuclei"), Probe("nikto"), Probe("nmap")
    ScanEngine(scanners=[nmap, nuclei, nikto], parallel=2).run(TARGET)

    assert (nmap.rate, nuclei.rate, nikto.rate) == (10.0, 5.0, 5.0)


def test_rate_split_has_a_floor_of_one():
    slow = Target(base_url="https://example.com", scope=Scope(rate_limit_rps=1.0))
    tools = [Probe("nuclei"), Probe("nikto"), Probe("wapiti")]
    ScanEngine(scanners=tools, parallel=3).run(slow)
    assert [t.rate for t in tools] == [1.0, 1.0, 1.0]


def test_request_cap_is_recorded_as_an_engine_error(local_url):
    def burst(context: ScanContext) -> None:
        for _ in range(3):
            with contextlib.suppress(RequestBudgetExceeded):
                context.http.get(f"{local_url}/x")

    target = Target(
        base_url=local_url, scope=Scope(max_requests=2, rate_limit_rps=1000.0)
    )
    session = ScanEngine(
        scanners=[Probe("header_checks", action=burst)],
        network_policy=NetworkPolicy(allow_private=True),
    ).run(target)

    assert any(e.startswith("[net] request cap max_requests=2") for e in session.errors)


def test_wapiti_relative_path_and_nuclei_absolute_url_give_one_finding():
    wapiti = finding("Cross Site Scripting", "/search?q=x", "wapiti")
    nuclei = finding("Reflected XSS", "https://example.com/search?q=y", "nuclei")
    originals = [wapiti.model_copy(deep=True), nuclei.model_copy(deep=True)]
    session = ScanEngine(
        scanners=[
            Probe("wapiti", findings=[wapiti]),
            Probe("nuclei", findings=[nuclei]),
        ]
    ).run(TARGET)

    assert len(session.correlated) == 1
    assert len(session.all_findings) == 1
    canonical = session.correlated[0].canonical
    assert canonical.fingerprint == session.all_findings[0].fingerprint
    assert {s for s, _ in session.correlated[0].sources} == {"wapiti", "nuclei"}
    assert (wapiti.url, nuclei.url) == (originals[0].url, originals[1].url)


def test_ignored_finding_is_kept_but_leaves_risk_remediation_and_exit_code():
    xss = finding("Reflected XSS", "https://example.com/s?q=1", "nuclei")
    ignore = IgnoreFile.model_validate(
        {
            "version": 1,
            "ignores": [
                {
                    "rule": "xss_reflected",
                    "reason": "accepted",
                    "author": "qa",
                    "expires": "2027-01-31",
                }
            ],
        }
    )
    session = ScanEngine(scanners=[Probe("nuclei", findings=[xss])], ignore=ignore).run(
        TARGET
    )

    canonical = session.correlated[0].canonical
    assert canonical.suppression is not None
    assert session.risk_posture is RiskPosture.EXCELLENT
    assert session.remediation_steps == []
    assert exit_code(session, Severity.INFO) == 0
