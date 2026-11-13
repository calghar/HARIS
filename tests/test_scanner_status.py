import json
from pathlib import Path

import pytest

from haris.core.engine import ScanEngine
from haris.core.exit_codes import exit_code
from haris.core.scanner import BaseScanner
from haris.db.store import ScanStore
from haris.models import ScannerResult, ScanSession, ScanState, Target
from haris.models.scan_context import ScanContext
from haris.reporting import REPORTER_REGISTRY
from haris.reporting.json_report import JSONReporter
from haris.reporting.markdown_report import MarkdownReporter
from tests.test_engine_pipeline import TARGET, Probe

S = ScanState
NOTE = "phase 2 stopped at 300s"
SKIP_NOTE = "no TLS port found"
WAPITI_NOTE = "crawl seeded"


class StatusProbe(Probe):
    """Probe whose result carries a status and note in its metadata."""

    def __init__(self, name: str, status: str, **kwargs: object) -> None:
        super().__init__(name, **kwargs)  # type: ignore[arg-type]
        self.status = status

    def scan(self, target: Target, context: ScanContext | None = None) -> ScannerResult:
        result = super().scan(target, context)
        if self.status in {"partial", "skipped"}:
            result.metadata = {"status": self.status, "note": f"{self.name} note"}
        return result


def run_engine(*statuses: str) -> ScanSession:
    scanners: list[BaseScanner] = [
        StatusProbe(
            f"s{i}",
            status,
            errors=["boom"] if status == "failed" else None,
        )
        for i, status in enumerate(statuses)
    ]
    return ScanEngine(scanners=scanners, parallel=1).run(TARGET)


@pytest.mark.parametrize(
    ("statuses", "state", "code"),
    [
        (("partial", "completed"), S.COMPLETED, 0),
        (("partial",), S.COMPLETED, 0),
        (("skipped", "completed"), S.COMPLETED, 0),
        (("skipped", "skipped"), S.COMPLETED, 0),
        (("skipped", "failed"), S.FAILED, 2),
        (("partial", "failed"), S.INCOMPLETE, 2),
        (("completed", "failed", "skipped"), S.INCOMPLETE, 2),
    ],
)
def test_final_state_and_exit_code(statuses, state, code):
    session = run_engine(*statuses)
    assert session.scan_state is state
    assert exit_code(session, None) == code


def test_scanner_status_values_and_errors_win():
    session = ScanSession(
        session_id="s",
        target=TARGET,
        scanner_results=[
            ScannerResult(scanner_name="a"),
            ScannerResult(scanner_name="b", errors=["x"]),
            ScannerResult(
                scanner_name="c", metadata={"status": "partial", "note": "n"}
            ),
            ScannerResult(
                scanner_name="d", metadata={"status": "skipped", "note": "n"}
            ),
            ScannerResult(
                scanner_name="e",
                errors=["x"],
                metadata={"status": "partial", "note": "n"},
            ),
            ScannerResult(
                scanner_name="f",
                errors=["x"],
                metadata={"status": "skipped", "note": "n"},
            ),
        ],
    )
    assert session.scanner_status == {
        "a": "completed",
        "b": "failed",
        "c": "partial",
        "d": "skipped",
        "e": "failed",
        "f": "failed",
    }
    assert session.scanner_notes == {"c": "n", "d": "n", "e": "n", "f": "n"}


def test_partial_scanner_keeps_risk_posture_known():
    session = run_engine("partial")
    assert session.risk_posture.value != "unknown"


def noted_session() -> ScanSession:
    return ScanSession(
        session_id="s-notes",
        target=Target(base_url="https://example.com"),
        scan_state=S.COMPLETED,
        scanners_used=["nuclei", "sslyze", "wapiti"],
        scanner_results=[
            ScannerResult(
                scanner_name="nuclei",
                metadata={"status": "partial", "note": NOTE},
            ),
            ScannerResult(
                scanner_name="sslyze",
                metadata={"status": "skipped", "note": SKIP_NOTE},
            ),
            ScannerResult(scanner_name="wapiti", metadata={"note": WAPITI_NOTE}),
        ],
    )


def test_json_report_carries_status_and_notes():
    data = json.loads(JSONReporter().generate(noted_session()))
    assert data["scanner_status"] == {
        "nuclei": "partial",
        "sslyze": "skipped",
        "wapiti": "completed",
    }
    assert data["scanner_notes"] == {
        "nuclei": NOTE,
        "sslyze": SKIP_NOTE,
        "wapiti": WAPITI_NOTE,
    }


def test_json_report_notes_empty_without_notes():
    data = json.loads(JSONReporter().generate(run_engine("completed")))
    assert data["scanner_notes"] == {}


@pytest.mark.parametrize("fmt", sorted(set(REPORTER_REGISTRY) - {"csv"}))
def test_every_reporter_but_csv_shows_every_note(fmt):
    report = REPORTER_REGISTRY[fmt]().generate(noted_session())
    assert NOTE in report
    assert SKIP_NOTE in report
    assert WAPITI_NOTE in report


def test_markdown_does_not_call_partial_or_skipped_scanners_failed():
    session = noted_session()
    session.scan_state = S.INCOMPLETE
    session.scanner_results.append(ScannerResult(scanner_name="zap", errors=["x"]))
    text = MarkdownReporter().generate(session)
    assert "scanners not completed: zap" in text


def test_status_and_note_survive_the_database(tmp_path: Path):
    store = ScanStore(tmp_path / "status.db")
    store.save_session(noted_session())

    loaded = store.load_session("s-notes")
    record = store.get_scan_record("s-notes")

    assert loaded is not None
    assert record is not None
    assert loaded.scanner_status == noted_session().scanner_status
    assert loaded.scanner_notes == {
        "nuclei": NOTE,
        "sslyze": SKIP_NOTE,
        "wapiti": WAPITI_NOTE,
    }
    assert record["scanner_status"] == {
        "nuclei": "partial",
        "sslyze": "skipped",
        "wapiti": "completed",
    }
