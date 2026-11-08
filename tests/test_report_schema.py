import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

from haris.diff import load_report
from haris.reporting.json_report import JSONReporter
from haris.reporting.report_schema import (
    SCHEMA_PATH,
    FindingRecord,
    ReportDocument,
    schema_text,
)
from tests.report_sessions import make_finding, make_session

FIXTURE_0_6_2 = Path(__file__).parent / "fixtures" / "report_0_6_2.json"


def test_checked_in_schema_matches_models():
    """Run `python -m haris.reporting.report_schema` when this fails."""
    assert SCHEMA_PATH.read_text(encoding="utf-8") == schema_text()


def test_finding_record_covers_every_serialised_key():
    keys = set(make_finding().to_dict())
    assert keys <= set(FindingRecord.model_fields), keys - set(
        FindingRecord.model_fields
    )


@pytest.fixture
def validator() -> Draft202012Validator:
    return Draft202012Validator(json.loads(SCHEMA_PATH.read_text(encoding="utf-8")))


def test_generated_report_validates_and_keeps_0_6_keys(validator):
    data = json.loads(JSONReporter().generate(make_session()))
    validator.validate(data)
    assert {
        "meta",
        "risk_posture",
        "summary",
        "findings",
        "remediation",
        "errors",
    } <= set(data)
    assert {"scan_state", "scanner_status", "correlated"} <= set(data)
    canonical = data["correlated"][0]
    assert canonical["sources"] == [["wapiti", canonical["observation_id"]]]
    assert canonical["fingerprint"] == "a" * 64
    assert canonical["verification"]["tier"] == "replay_verified"
    assert data["correlated"][1]["suppression"]["reason"] == "accepted risk"


def test_0_6_2_report_validates_and_loads(validator):
    """A 0.6 JSON report without verification keys still loads."""
    data = json.loads(FIXTURE_0_6_2.read_text(encoding="utf-8"))
    validator.validate(data)
    assert (
        ReportDocument.model_validate(data).findings[0].verification.tier
        == "unverified"
    )
    report = load_report(FIXTURE_0_6_2)
    assert report.findings["931357e981e1"].finding.title.startswith("Cross Site")


def test_generated_0_7_report_loads_through_diff(tmp_path):
    path = tmp_path / "report_0_7.json"
    JSONReporter().write(make_session(), path)
    loaded = load_report(path)
    assert set(loaded.findings) == {"f1", "f2", "f3"}
    assert loaded.completed == {"wapiti"}
