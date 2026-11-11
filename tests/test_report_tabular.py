import csv
import io
import xml.etree.ElementTree as ET

from haris.reporting.csv_report import COLUMNS, CSVReporter
from haris.reporting.junit_report import JUnitReporter
from tests.report_sessions import make_finding, make_session

TITLE = 'a, "quoted"\nsecond line'


def _rows(text: str) -> list[dict[str, str]]:
    return list(csv.DictReader(io.StringIO(text, newline="")))


def test_csv_round_trips_commas_quotes_newlines():
    session = make_session([make_finding(title=TITLE, description="x,y\r\nz")])
    [row] = _rows(CSVReporter().generate(session))
    assert row["title"] == TITLE
    assert row["description"] == "x,y\r\nz"
    assert tuple(row) == COLUMNS


def test_csv_neutralises_formula_cells():
    session = make_session(
        [
            make_finding(evidence='=HYPERLINK("http://x")', title="+cmd", scanner="@a"),
            make_finding(finding_id="g", remediation="-1+1", parameter="\t=x"),
        ]
    )
    first, second = _rows(CSVReporter().generate(session))
    assert first["evidence"] == '\'=HYPERLINK("http://x")'
    assert first["title"] == "'+cmd" and first["scanner"] == "'@a"
    assert second["remediation"] == "'-1+1" and second["parameter"] == "'\t=x"


def test_csv_status_column_lists_every_finding():
    rows = _rows(CSVReporter().generate(make_session()))
    assert [r["status"] for r in rows] == ["active", "suppressed", "refuted"]
    assert rows[0]["verification"] == "replay_verified"


def test_junit_one_testcase_per_finding_failing_only_when_active():
    root = ET.fromstring(JUnitReporter().generate(make_session()))
    suite = root.find("testsuite")
    assert suite is not None
    assert (suite.get("tests"), suite.get("failures"), suite.get("skipped")) == (
        "3",
        "1",
        "2",
    )
    cases = suite.findall("testcase")
    failing = [c for c in cases if c.find("failure") is not None]
    skipped = {c.get("name", ""): c.find("skipped") for c in cases if c not in failing}
    assert len(failing) == 1
    failure = failing[0].find("failure")
    assert failure is not None and failure.get("type") == "high"
    assert failure.text and "URL: https://example.com/search?q=x" in failure.text
    assert {s.get("message") for s in skipped.values() if s is not None} == {
        "suppressed: accepted risk",
        "refuted",
    }


def test_junit_strips_xml_illegal_characters_and_escapes_markup():
    session = make_session(
        [make_finding(title="a\x00b<&>", evidence="\x1b[31m</failure><x/>")]
    )
    xml = JUnitReporter().generate(session)
    root = ET.fromstring(xml)
    case = root.find("testsuite/testcase")
    assert case is not None and "\x00" not in (case.get("name") or "")
    failure = case.find("failure")
    assert failure is not None and "</failure><x/>" in (failure.text or "")
    assert root.find("testsuite/testcase/x") is None
