import hashlib
import json
from pathlib import Path

from jsonschema import Draft4Validator

from haris.diff import report_from_session
from haris.models import ScanState
from haris.reporting import REPORTER_REGISTRY
from haris.reporting.sarif_report import FINGERPRINT_KEY, SARIFReporter
from tests.report_sessions import make_finding, make_session

FIXTURES = Path(__file__).parent / "fixtures"
SCHEMA_FILE = FIXTURES / "sarif-schema-2.1.0.json"


def _sarif(session, baseline=None):
    return json.loads(SARIFReporter(baseline=baseline).generate(session))


def _by_id(doc, finding_class):
    return next(r for r in doc["runs"][0]["results"] if r["ruleId"] == finding_class)


def test_vendored_schema_matches_recorded_checksum():
    recorded = (FIXTURES / "sarif-schema-2.1.0.source.txt").read_text().split()
    assert hashlib.sha256(SCHEMA_FILE.read_bytes()).hexdigest() == recorded[-1]


def test_output_validates_against_sarif_2_1_0_schema():
    schema = json.loads(SCHEMA_FILE.read_text(encoding="utf-8"))
    doc = _sarif(make_session())
    Draft4Validator(schema).validate(doc)
    assert doc["version"] == "2.1.0"


def test_fingerprint_rule_level_and_request_response():
    doc = _sarif(make_session())
    result = _by_id(doc, "xss_reflected")
    assert result["partialFingerprints"] == {FINGERPRINT_KEY: "a" * 64}
    assert result["level"] == "error"
    assert result["webRequest"]["method"] == "GET"
    assert result["webRequest"]["headers"] == {"Accept": "text/html"}
    assert result["webResponse"]["statusCode"] == 200
    assert result["webResponse"]["body"]["text"] == "<html><x></html>"
    assert "suppressions" not in result
    rules = doc["runs"][0]["tool"]["driver"]["rules"]
    assert rules[result["ruleIndex"]]["id"] == "xss_reflected"
    assert rules[result["ruleIndex"]]["properties"]["security-severity"] == "8.0"


def test_suppressed_and_refuted_findings_carry_suppressions():
    doc = _sarif(make_session())
    suppressed = _by_id(doc, "missing_hsts")["suppressions"][0]
    assert suppressed["justification"] == "suppressed: accepted risk"
    assert suppressed["properties"]["author"] == "qa"
    refuted = _by_id(doc, "exposed_backup")["suppressions"][0]
    assert refuted["justification"] == "refuted"
    assert (refuted["kind"], refuted["status"]) == ("external", "accepted")


def test_request_falls_back_to_finding_fields_without_exchange():
    session = make_session([make_finding(method="POST")])
    result = _sarif(session)["runs"][0]["results"][0]
    assert result["webRequest"] == {
        "target": "https://example.com/search?q=x",
        "method": "POST",
    }
    assert result["webResponse"] == {"body": {"text": "<html>x</html>"}}


def test_baseline_states_new_unchanged_absent():
    old = make_session([make_finding(), make_finding(finding_id="gone")])
    current = make_session([make_finding(), make_finding(finding_id="fresh")])
    doc = _sarif(current, baseline=report_from_session(old))
    states = [r["baselineState"] for r in doc["runs"][0]["results"]]
    assert sorted(states) == ["absent", "new", "unchanged"]


def test_no_baseline_state_without_baseline():
    results = _sarif(make_session())["runs"][0]["results"]
    assert all("baselineState" not in r for r in results)


def test_failed_scan_reported_in_invocation():
    session = make_session([])
    session.scan_state = ScanState.FAILED
    session.errors = ["[nuclei] timeout"]
    invocation = _sarif(session)["runs"][0]["invocations"][0]
    assert invocation["executionSuccessful"] is False
    assert invocation["toolExecutionNotifications"][0]["message"]["text"].endswith(
        "timeout"
    )


def test_sarif_csv_junit_registered():
    assert {"sarif", "csv", "junit"} <= set(REPORTER_REGISTRY)
