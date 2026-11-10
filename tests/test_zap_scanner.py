import json
import re
import stat
from pathlib import Path
from typing import Any
from unittest.mock import patch

import pytest
import yaml

from haris.config.loader import load_config
from haris.core.decorators import scanner_registry
from haris.core.profiles import PROFILES
from haris.core.runner import ScanRunner
from haris.core.vuln_class import get_registry
from haris.data.scanner_config import get_zap_config
from haris.models import Confidence, ScanContext, Scope, Severity, Target
from haris.models.target import AuthConfig
from haris.scanners import SCANNER_REGISTRY
from haris.scanners.process import ToolTimeoutError
from haris.scanners.zap_plan import (
    REPORT_FILE,
    exclude_regex,
    include_regex,
)
from haris.scanners.zap_scanner import LAUNCHERS, ZapScanner

FIXTURE = Path(__file__).parent / "fixtures" / "scanners" / "zap" / "traditional.json"
PUBLIC_IP = "93.184.216.34"
SECRET = "zap-secret-token"


def _target(url: str = "https://example.com/app", **scope: Any) -> Target:
    return Target(base_url=url, scope=Scope(**scope))


def _public(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "haris.scanners.zap_scanner.system_resolver",
        lambda host, port: [PUBLIC_IP],
    )


def _install(tmp_path: Path, *names: str) -> None:
    for name in names:
        binary = tmp_path / name
        binary.write_text("#!/bin/sh\nexit 0\n")
        binary.chmod(0o755)


@pytest.fixture
def report() -> str:
    return FIXTURE.read_text()


class TestPlan:
    def test_jobs_include_exclude_and_report(self) -> None:
        target = _target(excluded_paths=["/logout", "a.b"])
        plan = ZapScanner()._plan(target, Path("/tmp/zap-out"), None)
        context = plan["env"]["contexts"][0]
        assert context["urls"] == ["https://example.com/app"]
        assert context["includePaths"] == [include_regex("example.com")]
        assert context["excludePaths"] == [
            exclude_regex("/logout"),
            exclude_regex("a.b"),
        ]
        assert re.escape("a.b") in context["excludePaths"][1]
        assert (
            re.search(include_regex("example.com"), "https://notexample.com/") is None
        )
        assert (
            re.search(exclude_regex("/logout"), "https://logout.example.com/") is None
        )
        assert re.search(exclude_regex("a.b"), "https://example.com/axb") is None
        assert re.search(exclude_regex("a.b"), "https://example.com/a.b")
        jobs = [job["type"] for job in plan["jobs"]]
        assert jobs == ["spider", "passiveScan-wait", "activeScan", "report"]
        report = plan["jobs"][-1]["parameters"]
        assert report["template"] == "traditional-json"
        assert report["reportFile"] == REPORT_FILE
        active = plan["jobs"][-2]["parameters"]
        assert active["maxScanDurationInMins"] == 15
        assert plan["jobs"][0]["parameters"]["maxDuration"] == 5

    def test_non_default_port_kept(self) -> None:
        plan = ZapScanner()._plan(
            _target("https://example.com:8443/app"), Path("."), None
        )
        assert plan["env"]["contexts"][0]["urls"] == ["https://example.com:8443/app"]

    def test_rate_sets_delay(self) -> None:
        plan = ZapScanner()._plan(_target(), Path("."), ScanContext(tool_rate_rps=10))
        active = next(job for job in plan["jobs"] if job["type"] == "activeScan")
        assert active["parameters"]["delayInMs"] == 100
        assert active["parameters"]["threadPerHost"] == 1

    def test_auth_is_a_replacer_rule_not_left_out(self) -> None:
        target = _target()
        target.auth = AuthConfig(
            method="header", header_name="Authorization", header_value=SECRET
        )
        plan = ZapScanner()._plan(target, Path("."), None)
        rule = plan["jobs"][0]["rules"][0]
        assert plan["jobs"][0]["type"] == "replacer"
        assert rule["matchType"] == "req_header"
        assert rule["matchString"] == "Authorization"
        assert rule["replacementString"] == SECRET


class TestRun:
    def test_plan_mode_argv_and_cleanup(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        caplog: pytest.LogCaptureFixture,
        report: str,
    ) -> None:
        _public(monkeypatch)
        _install(tmp_path, "zap", "zap.sh")
        monkeypatch.setenv("PATH", str(tmp_path))
        target = _target()
        target.auth = AuthConfig(
            method="header", header_name="Authorization", header_value=SECRET
        )
        seen: dict[str, Any] = {}

        def fake(cmd: list[str], timeout: float) -> tuple[int, str, str]:
            plan_path = Path(cmd[cmd.index("-autorun") + 1])
            seen["cmd"] = cmd
            seen["mode"] = stat.S_IMODE(plan_path.stat().st_mode)
            seen["dir"] = plan_path.parent
            loaded = yaml.safe_load(plan_path.read_text())
            assert loaded["jobs"][0]["rules"][0]["replacementString"] == SECRET
            (plan_path.parent / REPORT_FILE).write_text(
                report.replace("<script>", SECRET)
            )
            return 0, "", ""

        with (
            patch("haris.scanners.base.run_process", side_effect=fake),
            caplog.at_level("DEBUG"),
        ):
            result = ZapScanner().scan(target)
        assert seen["cmd"][0] == "zap.sh"
        assert seen["cmd"][1:3] == ["-cmd", "-autorun"]
        assert "-dir" in seen["cmd"] and "-silent" in seen["cmd"]
        assert SECRET not in seen["cmd"]
        assert SECRET not in caplog.text
        assert seen["mode"] == 0o600
        assert not seen["dir"].exists()
        assert result.findings
        assert SECRET not in result.raw_output
        assert all(SECRET not in item.evidence for item in result.findings)

    def test_falls_back_to_zap_name(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _public(monkeypatch)
        _install(tmp_path, "zap")
        monkeypatch.setenv("PATH", str(tmp_path))
        seen: dict[str, str] = {}

        def fake(cmd: list[str], timeout: float) -> tuple[int, str, str]:
            seen["launcher"] = cmd[0]
            return 0, "", ""

        with patch("haris.scanners.base.run_process", side_effect=fake):
            ZapScanner().scan(_target())
        assert seen["launcher"] == "zap"
        assert LAUNCHERS[0] == "zap.sh"

    def test_missing_tool(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("PATH", str(tmp_path))
        result = ZapScanner().scan(_target())
        assert result.findings == []
        assert "not on PATH" in result.errors[0]
        assert "zap.sh" in result.errors[0]

    def test_timeout_keeps_partial_report(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, report: str
    ) -> None:
        _public(monkeypatch)
        _install(tmp_path, "zap.sh")
        monkeypatch.setenv("PATH", str(tmp_path))

        def fake(cmd: list[str], timeout: float) -> tuple[int, str, str]:
            plan = Path(cmd[cmd.index("-autorun") + 1])
            (plan.parent / REPORT_FILE).write_text(report)
            raise ToolTimeoutError("timed out", "", "")

        with patch("haris.scanners.base.run_process", side_effect=fake):
            result = ZapScanner({"timeout": 1}).scan(_target())
        assert result.findings
        assert result.errors == ["zap timed out after 1s; partial results kept"]

    def test_malformed_json(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _public(monkeypatch)
        _install(tmp_path, "zap.sh")
        monkeypatch.setenv("PATH", str(tmp_path))

        def fake(cmd: list[str], timeout: float) -> tuple[int, str, str]:
            plan = Path(cmd[cmd.index("-autorun") + 1])
            (plan.parent / REPORT_FILE).write_text("{")
            return 0, "", ""

        with patch("haris.scanners.base.run_process", side_effect=fake):
            result = ZapScanner().scan(_target())
        assert result.findings == []
        assert ZapScanner().parse_results("[") == []
        assert ZapScanner().parse_results("[]") == []


class TestParse:
    def test_fixture_fields(self, report: str) -> None:
        findings = ZapScanner().parse_results(report)
        assert len(findings) == 6
        xss = findings[0]
        cfg = get_zap_config()
        assert xss.severity is Severity[cfg["severity_map"]["3"]]
        assert xss.confidence is Confidence[cfg["confidence_map"]["2"]]
        assert xss.url == "https://example.com/search?q=1"
        assert xss.parameter == "q"
        assert xss.cwe_id == "CWE-79"
        assert "40012" in xss.tags
        assert xss.scanner == "zap"
        assert findings[1].method == "POST"
        assert findings[1].parameter == "comments"
        registry = get_registry()
        assert registry.classify(xss) == "xss_reflected"
        assert registry.classify(findings[2]) == "sqli_error"
        assert registry.classify(findings[3]) == "path_traversal"
        assert registry.classify(findings[4]) == "cookie_missing_httponly"
        assert registry.classify(findings[5]) == "missing_header"
        assert findings[3].confidence is Confidence[cfg["confidence_map"]["1"]]

    def test_instance_cap(self, report: str) -> None:
        assert len(ZapScanner({"max_instances": 1}).parse_results(report)) == 1

    def test_unknown_codes_use_defaults(self) -> None:
        raw = json.dumps(
            {
                "site": [
                    {
                        "alerts": [
                            {
                                "alert": "Odd",
                                "riskcode": "9",
                                "confidence": "9",
                                "cweid": "-1",
                                "instances": [{"uri": "https://example.com/x"}],
                            }
                        ]
                    }
                ]
            }
        )
        found = ZapScanner().parse_results(raw)[0]
        assert found.severity is Severity.INFO
        assert found.confidence is Confidence.TENTATIVE
        assert found.cwe_id == ""


class TestPreflight:
    def test_out_of_scope_does_not_start(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _install(tmp_path, "zap.sh")
        monkeypatch.setenv("PATH", str(tmp_path))

        def boom(host: str, port: int) -> list[str]:
            raise AssertionError(host)

        monkeypatch.setattr("haris.scanners.zap_scanner.system_resolver", boom)
        with patch("haris.scanners.base.run_process") as run:
            result = ZapScanner().scan(
                _target("https://example.com/secret", excluded_paths=["/secret"])
            )
        assert run.call_count == 0
        assert "outside the authorised scope" in result.errors[0]

    def test_private_address_refused(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _install(tmp_path, "zap.sh")
        monkeypatch.setenv("PATH", str(tmp_path))
        with patch("haris.scanners.base.run_process") as run:
            literal = ZapScanner().scan(_target("http://127.0.0.1/admin"))
            monkeypatch.setattr(
                "haris.scanners.zap_scanner.system_resolver",
                lambda host, port: ["10.1.1.1"],
            )
            named = ZapScanner().scan(_target("http://internal.test/admin"))
        assert run.call_count == 0
        assert "blocked address" in literal.errors[0]
        assert "blocked address" in named.errors[0]


class TestRegistration:
    def test_not_in_any_profile(self) -> None:
        assert all("zap" not in profile.scanners for profile in PROFILES.values())

    def test_registered_and_disabled_by_default(self) -> None:
        assert SCANNER_REGISTRY["zap"] is ZapScanner
        assert scanner_registry()["zap"] is ZapScanner
        zap = next(item for item in load_config().scanners if item.name == "zap")
        assert zap.enabled is False

    def test_scanners_flag_selects_zap(self) -> None:
        runner = ScanRunner(_target(), scanner_names=["zap"])
        selected = runner._build_scanners()
        assert [scanner.name for scanner in selected] == ["zap"]
