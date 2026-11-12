import json
import logging
import shutil
import sqlite3
from pathlib import Path

import pytest

from haris.models import Confidence, Finding, Target
from haris.scanners.base import TIMEOUT_RETURNCODE, ToolRun
from haris.scanners.wapiti_scanner import SCAN_KILL_GRACE_SECONDS, WapitiScanner
from haris.scanners.wapiti_session import session_report
from tests.conftest import bound_context

FIXTURE = Path(__file__).parent / "fixtures" / "scanners" / "wapiti" / "dvwa_session.db"
SECRET = "planted-session-secret-7c2e"
MAX_SCAN_TIME = 40
VULN_COUNTS = {
    "Cleartext Submission of Password": 10,
    "Command execution": 2,
    "Open Redirect": 2,
    "Path Traversal": 1,
    "Reflected Cross Site Scripting": 5,
    "SQL Injection": 3,
    "Server Side Request Forgery": 1,
}
ANOMALY_COUNTS = {"Internal Server Error": 3}


def _session(tmp_path: Path) -> Path:
    directory = tmp_path / "session"
    directory.mkdir()
    shutil.copy(FIXTURE, directory / "sample.db")
    return directory


def _counts(findings: list[Finding]) -> tuple[dict[str, int], dict[str, int]]:
    vulnerabilities: dict[str, int] = {}
    anomalies: dict[str, int] = {}
    for finding in findings:
        if finding.title.startswith("Anomaly ("):
            category = finding.title.removeprefix("Anomaly (").split("):", 1)[0]
            anomalies[category] = anomalies.get(category, 0) + 1
            continue
        category = finding.title.split(":", 1)[0]
        vulnerabilities[category] = vulnerabilities.get(category, 0) + 1
    return vulnerabilities, anomalies


class TestSessionReport:
    def test_sample_database_yields_the_recorded_findings(self, tmp_path: Path) -> None:
        raw = session_report(_session(tmp_path))
        findings = WapitiScanner().parse_results(raw)
        vulnerabilities, anomalies = _counts(findings)
        assert vulnerabilities == VULN_COUNTS
        assert anomalies == ANOMALY_COUNTS
        assert sum(vulnerabilities.values()) == 24
        assert sum(anomalies.values()) == 3
        assert all(
            finding.confidence == Confidence.FIRM
            for finding in findings
            if not finding.title.startswith("Anomaly (")
        )
        assert all(
            finding.confidence == Confidence.TENTATIVE
            for finding in findings
            if finding.title.startswith("Anomaly (")
        )

    def test_planted_secret_is_absent(self, tmp_path: Path) -> None:
        directory = _session(tmp_path)
        database = next(directory.glob("*.db"))
        connection = sqlite3.connect(database)
        try:
            connection.execute(
                "UPDATE paths SET headers = ?, referer = ?", (SECRET, SECRET)
            )
            connection.execute(
                "UPDATE responses SET headers = ?, body = ?", (SECRET, SECRET)
            )
            connection.commit()
        finally:
            connection.close()
        assert SECRET not in session_report(directory)

    def test_comma_in_wstg_becomes_a_list(self, tmp_path: Path) -> None:
        directory = _session(tmp_path)
        database = next(directory.glob("*.db"))
        connection = sqlite3.connect(database)
        try:
            connection.execute(
                """
                UPDATE payloads SET wstg = ?
                WHERE rowid = (
                    SELECT rowid FROM payloads WHERE type = 'vulnerability' LIMIT 1
                )
                """,
                ("WSTG-A,WSTG-B",),
            )
            connection.commit()
        finally:
            connection.close()
        report = json.loads(session_report(directory))
        lists = [
            item["wstg"]
            for groups in report["vulnerabilities"].values()
            for item in groups
            if isinstance(item["wstg"], list)
        ]
        assert lists == [["WSTG-A", "WSTG-B"]]

    def test_missing_directory_returns_empty(
        self, tmp_path: Path, caplog: pytest.LogCaptureFixture
    ) -> None:
        with caplog.at_level(logging.DEBUG):
            assert session_report(tmp_path / "missing") == ""
        assert any(record.levelno == logging.DEBUG for record in caplog.records)

    def test_missing_payloads_table_returns_empty(
        self, tmp_path: Path, caplog: pytest.LogCaptureFixture
    ) -> None:
        database = tmp_path / "empty.db"
        connection = sqlite3.connect(database)
        try:
            connection.execute("CREATE TABLE paths (path_id INTEGER)")
        finally:
            connection.close()
        with caplog.at_level(logging.DEBUG):
            assert session_report(tmp_path) == ""
        assert any(record.levelno == logging.DEBUG for record in caplog.records)

    def test_corrupt_file_returns_empty(
        self, tmp_path: Path, caplog: pytest.LogCaptureFixture
    ) -> None:
        (tmp_path / "bad.db").write_bytes(b"not a database")
        with caplog.at_level(logging.DEBUG):
            assert session_report(tmp_path) == ""
        assert any(record.levelno == logging.DEBUG for record in caplog.records)


def _available(_binary: str) -> bool:
    return True


class TestScanRecovery:
    def test_timeout_recovers_findings(self, monkeypatch: pytest.MonkeyPatch) -> None:
        def run(cmd: list[str], _output_file: Path, _timeout: int) -> ToolRun:
            session = Path(cmd[cmd.index("--store-session") + 1])
            shutil.copy(FIXTURE, session / "scan.db")
            return ToolRun(TIMEOUT_RETURNCODE, "", "", True)

        scanner = WapitiScanner({"max_scan_time": MAX_SCAN_TIME})
        monkeypatch.setattr(scanner, "_check_tool_available", _available)
        monkeypatch.setattr(scanner, "_run_to_file", run)
        result = scanner.scan(Target(base_url="http://127.0.0.1:9"), bound_context())
        waited = MAX_SCAN_TIME + SCAN_KILL_GRACE_SECONDS
        assert len(result.findings) == 27
        assert result.errors == [
            f"wapiti timed out after {waited}s; "
            "27 findings recovered from its session database"
        ]

    def test_nonzero_exit_without_a_report_recovers(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        def run(cmd: list[str], _output_file: Path, _timeout: int) -> ToolRun:
            session = Path(cmd[cmd.index("--store-session") + 1])
            shutil.copy(FIXTURE, session / "scan.db")
            return ToolRun(3, "scanner failed", "", False)

        scanner = WapitiScanner()
        monkeypatch.setattr(scanner, "_check_tool_available", _available)
        monkeypatch.setattr(scanner, "_run_to_file", run)
        result = scanner.scan(Target(base_url="http://127.0.0.1:9"), bound_context())
        assert len(result.findings) == 27
        assert result.errors == ["wapiti exited with code 3: scanner failed"]

    def test_successful_report_does_not_read_the_session(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        report = json.dumps(
            {
                "vulnerabilities": {
                    "SQL Injection": [
                        {
                            "level": 2,
                            "info": "normal-report-marker",
                            "path": "http://127.0.0.1/a",
                            "method": "GET",
                        }
                    ]
                }
            }
        )

        def run(cmd: list[str], _output_file: Path, _timeout: int) -> ToolRun:
            session = Path(cmd[cmd.index("--store-session") + 1])
            shutil.copy(FIXTURE, session / "scan.db")
            return ToolRun(0, "", report, False)

        def refuse(_session_dir: Path) -> str:
            raise AssertionError("session database was read")

        scanner = WapitiScanner()
        monkeypatch.setattr(scanner, "_check_tool_available", _available)
        monkeypatch.setattr(scanner, "_run_to_file", run)
        monkeypatch.setattr("haris.scanners.wapiti_scanner.session_report", refuse)
        result = scanner.scan(Target(base_url="http://127.0.0.1:9"), bound_context())
        assert result.errors == []
        assert len(result.findings) == 1
        assert result.findings[0].description == "normal-report-marker"
