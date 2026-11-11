import json
import re
from pathlib import Path

from haris.agent.stages import note_stage
from haris.agent.turn import ANNOTATION_CAP, remember
from haris.db.store import ScanStore
from haris.models import CorrelatedFinding, Finding, ScanSession
from haris.reporting.html_report import HTMLReporter
from haris.reporting.json_report import JSONReporter
from haris.reporting.markdown_report import MarkdownReporter
from haris.reporting.report_schema import ReportDocument
from haris.reporting.sarif_report import SARIFReporter
from tests.report_sessions import make_finding, make_session

NOTE = "claim `` ```` <script>alert(1)</script>"


def _annotated() -> ScanSession:
    session = make_session()
    session.correlated = [
        CorrelatedFinding(canonical=f, consensus_score=0.5)
        for f in session.all_findings
    ]
    remember(session, session.correlated[0], NOTE)
    for stage in ("correlate", "agent", "report"):
        note_stage(session, stage)
    return session


def test_annotation_and_stages_survive_dict_and_database(tmp_path: Path) -> None:
    """Both new fields persist through to_dict/from_dict and a DB save/load."""
    session = _annotated()
    finding = session.correlated[0].canonical

    assert Finding.from_dict(finding.to_dict()).agent_annotation == NOTE
    store = ScanStore(tmp_path / "f.db")
    store.save_session(session)
    loaded = store.load_session(session.session_id)

    assert loaded is not None
    assert loaded.stage_log == ["correlate", "agent", "report"]
    assert loaded.all_findings[0].agent_annotation == NOTE
    assert loaded.correlated[0].canonical.agent_annotation == NOTE
    assert loaded.all_findings[1].agent_annotation == ""


def test_0_6_data_without_the_keys_loads_with_defaults() -> None:
    legacy = make_finding().to_dict()
    del legacy["agent_annotation"]
    report = json.loads(JSONReporter().generate(make_session()))
    del report["stage_log"]

    assert Finding.from_dict(legacy).agent_annotation == ""
    assert ReportDocument.model_validate(report).stage_log == []
    assert (
        ScanSession.model_validate(
            {"session_id": "s", "target": {"base_url": "https://example.com"}}
        ).stage_log
        == []
    )


def test_remember_caps_the_annotation_and_ignores_empty_text() -> None:
    session = _annotated()
    case = session.correlated[0]

    remember(session, case, "x" * (ANNOTATION_CAP + 50))
    remember(session, case, "")

    assert len(case.canonical.agent_annotation) == ANNOTATION_CAP
    assert len(session.all_findings[0].agent_annotation) == ANNOTATION_CAP


def test_json_and_sarif_carry_the_annotation() -> None:
    session = _annotated()

    data = json.loads(JSONReporter().generate(session))
    sarif = json.loads(SARIFReporter().generate(session))
    results = sarif["runs"][0]["results"]

    assert data["stage_log"] == ["correlate", "agent", "report"]
    assert data["findings"][0]["agent_annotation"] == NOTE
    assert data["correlated"][0]["agent_annotation"] == NOTE
    assert results[0]["properties"]["agentAnnotation"] == NOTE
    assert "agentAnnotation" not in results[1]["properties"]


def test_markdown_fences_the_annotation_longer_than_any_backtick_run() -> None:
    markdown = MarkdownReporter().generate(_annotated())

    escaped = NOTE.replace("<", "&lt;").replace(">", "&gt;")

    assert max(len(m) for m in re.findall(r"`+", NOTE)) == 4
    assert f"**Agent note:**\n`````\n{escaped}\n`````" in markdown


def test_html_escapes_the_annotation() -> None:
    page = HTMLReporter().generate(_annotated())

    assert "<script>alert(1)</script>" not in page
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in page
