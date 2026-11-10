"""Golden-fixture and regression tests for nikto, wapiti, sslyze and nmap.

Fixtures are real tool output; see tests/fixtures/scanners/README.md.
"""

import json
from collections.abc import Callable
from pathlib import Path
from typing import Any
from unittest.mock import patch

import pytest

from haris.data.scanner_config import (
    get_wapiti_category_tags,
    get_wapiti_excluded_modules,
)
from haris.models import Severity
from haris.models.target import AuthConfig, Scope, Target
from haris.scanners.argv_policy import ExtraArgsError
from haris.scanners.nikto_scanner import NiktoScanner, _classify_finding
from haris.scanners.nmap_scanner import NmapScanner
from haris.scanners.process import ToolTimeoutError
from haris.scanners.sslyze_scanner import SSLyzeScanner
from haris.scanners.wapiti_scanner import (
    FALLBACK_TAGS,
    SCAN_KILL_GRACE_SECONDS,
    WapitiScanner,
)
from haris.templates.adapters import NmapTemplateAdapter

FIXTURES = Path(__file__).parent / "fixtures" / "scanners"
HTTP_URL = "http://127.0.0.1:18080"
HTTPS_URL = "https://127.0.0.1:18443"


def fixture(name: str) -> str:
    return (FIXTURES / name).read_text()


def tool_writing(
    report: str, *, suffix: str = "", timeout: bool = False
) -> Callable[[list[str], float], tuple[int, str, str]]:
    """Fake ``run_process`` that writes *report* where the tool would."""

    def run(cmd: list[str], _timeout: float) -> tuple[int, str, str]:
        for flag in ("-output", "--output", "--json_out", "-oX"):
            if flag in cmd:
                Path(cmd[cmd.index(flag) + 1] + suffix).write_text(report)
        if timeout:
            raise ToolTimeoutError("timed out", "", "")
        return 0, "", ""

    return run


@pytest.fixture
def target() -> Target:
    return Target(base_url=HTTP_URL, scope=Scope())


def run_scan(scanner: Any, target: Target, runner: Callable[..., Any]) -> Any:
    with (
        patch.object(scanner, "_check_tool_available", return_value=True),
        patch("haris.scanners.base.run_process", side_effect=runner),
    ):
        return scanner.scan(target)


class TestNiktoGolden:
    def test_http_report(self) -> None:
        findings = NiktoScanner().parse_results(
            fixture("nikto/http.json"), base_url=HTTP_URL
        )
        assert len(findings) == 14
        assert all(f.url.startswith(HTTP_URL + "/") for f in findings)
        listing = next(f for f in findings if f.title == "Directory indexing found.")
        assert listing.url == f"{HTTP_URL}/admin/"
        assert listing.tags == ["directory_listing"]
        assert listing.evidence.startswith("Nikto test ")

    def test_https_report_keeps_scheme(self) -> None:
        findings = NiktoScanner().parse_results(
            fixture("nikto/https.json"), base_url=HTTPS_URL
        )
        assert len(findings) == 16
        assert all(f.url.startswith(HTTPS_URL + "/") for f in findings)

    def test_scheme_defaults_to_http_without_base_url(self) -> None:
        findings = NiktoScanner().parse_results(fixture("nikto/https.json"))
        assert all(f.url.startswith("http://") for f in findings)

    def test_scan_reads_report_nikto_writes(self, target: Target) -> None:
        """Nikto appends .json to -output; the scanner must read that file."""
        runner = tool_writing(fixture("nikto/http.json"), suffix=".json")
        result = run_scan(NiktoScanner(), target, runner)
        assert result.errors == []
        assert len(result.findings) == 14

    def test_timeout_keeps_partial_report(self, target: Target) -> None:
        runner = tool_writing(fixture("nikto/http.json"), suffix=".json", timeout=True)
        result = run_scan(NiktoScanner({"timeout": 5}), target, runner)
        assert len(result.findings) == 14
        assert result.errors == ["nikto timed out after 5s; partial results kept"]


class TestNiktoCommand:
    def test_no_useragent_extra_flag(self, target: Target) -> None:
        target.auth = AuthConfig(
            method="header", header_name="X-Token", header_value="tok-12345"
        )
        cmd = NiktoScanner()._build_command(target, "/tmp/stem")
        assert "-useragent-extra" not in cmd
        assert cmd[cmd.index("-Add-header") + 1] == "X-Token: tok-12345"

    def test_https_target_scheme_is_kept(self) -> None:
        https_target = Target(base_url="https://example.com:8443", scope=Scope())
        cmd = NiktoScanner()._build_command(https_target, "/tmp/stem")
        assert cmd[cmd.index("-host") + 1] == "https://example.com:8443"
        assert "http://example.com" not in " ".join(cmd)

    def test_output_has_no_extension_and_no_phone_home(self, target: Target) -> None:
        cmd = NiktoScanner()._build_command(target, "/tmp/stem")
        assert cmd[cmd.index("-output") + 1] == "/tmp/stem"
        assert "-nocheck" in cmd


class TestNiktoKeywords:
    @pytest.mark.parametrize(
        "msg",
        [
            "X-Frame-Options header is not present.",
            "The Permissions-Policy header lacks geolocation=()",
        ],
    )
    def test_substring_does_not_match(self, msg: str) -> None:
        tags, severity = _classify_finding(msg, "0")
        assert tags == ["security_misconfiguration"]
        assert severity == Severity.INFO

    def test_allowed_methods_still_match(self) -> None:
        _, severity = _classify_finding("OPTIONS: Allowed HTTP Methods: GET", "0")
        assert severity == Severity.MEDIUM

    def test_whole_word_eol_matches(self) -> None:
        tags, severity = _classify_finding("Server is eol", "0")
        assert "outdated_server" in tags
        assert severity == Severity.HIGH

    def test_golden_deprecated_header_is_info(self) -> None:
        findings = NiktoScanner().parse_results(fixture("nikto/http.json"))
        frame = next(f for f in findings if f.title.startswith("X-Frame-Options"))
        assert frame.severity == Severity.INFO


class TestWapitiGolden:
    def test_every_real_category_is_mapped(self) -> None:
        report = json.loads(fixture("wapiti/all_modules.json"))
        mapped = get_wapiti_category_tags()
        unmapped = sorted(set(report["classifications"]) - set(mapped))
        assert unmapped == []
        assert all(mapped[name] for name in report["classifications"])

    def test_default_report_tags(self) -> None:
        findings = WapitiScanner().parse_results(fixture("wapiti/default_modules.json"))
        by_title = {f.title.split(":")[0]: f.tags for f in findings}
        assert by_title["Reflected Cross Site Scripting"] == ["xss"]
        assert by_title["Path Traversal"] == ["directory_traversal"]
        assert by_title["Open Redirect"] == ["open_redirect"]
        assert len(findings) == 5

    @pytest.mark.parametrize(
        ("category", "tag"),
        [
            ("Server Side Request Forgery", "ssrf"),
            ("XML External Entity", "xxe"),
            ("Path Traversal", "directory_traversal"),
            ("Reflected Cross Site Scripting", "xss"),
        ],
    )
    def test_category_keeps_owasp_tag(self, category: str, tag: str) -> None:
        vuln = {"level": 3, "info": "x", "path": "/p", "method": "GET"}
        finding = WapitiScanner()._finding_from_vuln(category, vuln)
        assert tag in finding.tags

    def test_unknown_category_falls_back(self) -> None:
        vuln = {"level": 1, "info": "x", "path": "/p", "method": "GET"}
        finding = WapitiScanner()._finding_from_vuln("Brand New Module", vuln)
        assert finding.tags == FALLBACK_TAGS

    def test_scan_reads_report(self, target: Target) -> None:
        runner = tool_writing(fixture("wapiti/default_modules.json"))
        result = run_scan(WapitiScanner(), target, runner)
        assert result.errors == []
        assert len(result.findings) == 5

    def test_timeout_keeps_a_written_report(self, target: Target) -> None:
        runner = tool_writing(fixture("wapiti/default_modules.json"), timeout=True)
        result = run_scan(WapitiScanner(), target, runner)
        assert len(result.findings) == 5
        assert "its report was kept" in result.errors[0]

    def test_timeout_without_a_session_recovers_nothing(self, target: Target) -> None:
        runner = tool_writing("", timeout=True)
        limit = 40
        result = run_scan(WapitiScanner({"max_scan_time": limit}), target, runner)
        waited = limit + SCAN_KILL_GRACE_SECONDS
        assert result.findings == []
        assert result.errors == [
            f"wapiti timed out after {waited}s; no findings recovered"
        ]


class TestWapitiCommand:
    def test_overlapping_modules_dropped(self, target: Target) -> None:
        cmd = WapitiScanner()._build_command(
            target, "/tmp/out.json", "/tmp/wapiti-session"
        )
        assert cmd[cmd.index("--store-session") + 1] == "/tmp/wapiti-session"
        spec = cmd[cmd.index("--module") + 1]
        assert spec.startswith("common,")
        for name in get_wapiti_excluded_modules():
            assert f"-{name}" in spec.split(",")

    def test_explicit_modules_keep_exclusions(self, target: Target) -> None:
        scanner = WapitiScanner({"modules": ["xss", "sql"]})
        cmd = scanner._build_command(target, "/tmp/out.json", "/tmp/wapiti-session")
        modules = cmd[cmd.index("--module") + 1].split(",")
        assert modules[:2] == ["xss", "sql"]
        assert "-ssl" in modules

    def test_bug_report_disabled(self, target: Target) -> None:
        assert "--no-bugreport" in WapitiScanner()._build_command(
            target, "/tmp/o", "/tmp/wapiti-session"
        )


class TestWapitiRedaction:
    def test_auth_secrets_absent_from_result_and_logs(
        self, target: Target, caplog: pytest.LogCaptureFixture
    ) -> None:
        target.auth = AuthConfig(
            method="header",
            header_name="Authorization",
            header_value="Bearer wapiti-secret-token",
        )
        runner = tool_writing(fixture("wapiti/auth_headers.json"))
        with caplog.at_level("DEBUG"):
            result = run_scan(WapitiScanner(), target, runner)
        dump = result.model_dump_json() + caplog.text
        assert result.findings
        for secret in ("wapiti-secret-token", "wapiti-secret-key"):
            assert secret not in dump


class TestSslyzeGolden:
    def test_no_connectivity_does_not_crash(self) -> None:
        raw = fixture("sslyze/no_connectivity.json")
        assert SSLyzeScanner().parse_results(raw) == []
        assert SSLyzeScanner._scan_errors(raw) == [
            "sslyze scan of 127.0.0.1:18999 ended with status ERROR_NO_CONNECTIVITY"
        ]

    def test_scan_reports_no_connectivity(self, target: Target) -> None:
        runner = tool_writing(fixture("sslyze/no_connectivity.json"))
        result = run_scan(SSLyzeScanner(), target, runner)
        assert result.findings == []
        assert any("ERROR_NO_CONNECTIVITY" in e for e in result.errors)

    @pytest.mark.parametrize("replacement", [None, {"status": "ERROR", "result": None}])
    def test_null_command_results_do_not_crash(self, replacement: Any) -> None:
        report = json.loads(fixture("sslyze/modern_tls.json"))
        scan_result = report["server_scan_results"][0]["scan_result"]
        for key in scan_result:
            scan_result[key] = replacement
        assert SSLyzeScanner().parse_results(json.dumps(report)) == []

    def test_null_result_inside_completed_command(self) -> None:
        report = json.loads(fixture("sslyze/modern_tls.json"))
        scan_result = report["server_scan_results"][0]["scan_result"]
        for value in scan_result.values():
            value["result"] = None
        assert SSLyzeScanner().parse_results(json.dumps(report)) == []

    def test_legacy_protocols_flagged(self) -> None:
        titles = [
            f.title
            for f in SSLyzeScanner().parse_results(fixture("sslyze/legacy_tls.json"))
        ]
        assert "Deprecated protocol TLS 1.0 supported" in titles
        assert "Deprecated protocol TLS 1.1 supported" in titles

    def test_modern_config_has_no_protocol_findings(self) -> None:
        titles = [
            f.title
            for f in SSLyzeScanner().parse_results(fixture("sslyze/modern_tls.json"))
        ]
        assert titles == ["Certificate not trusted"]

    def test_invalid_json_returns_empty(self) -> None:
        assert SSLyzeScanner().parse_results("not json") == []
        assert SSLyzeScanner().parse_results("null") == []


class TestNmapGolden:
    def test_golden_report(self) -> None:
        findings = NmapScanner().parse_results(fixture("nmap/scan.xml"))
        titles = [f.title for f in findings]
        assert "Open port 18080/tcp: http" in titles
        assert "Server version disclosed: Apache httpd 2.2.8" in titles
        assert len(findings) == 4

    def test_scan_reads_report(self, target: Target) -> None:
        runner = tool_writing(fixture("nmap/scan.xml"))
        result = run_scan(NmapScanner(), target, runner)
        assert result.errors == []
        assert len(result.findings) == 4

    def test_timeout_keeps_partial_report(self, target: Target) -> None:
        runner = tool_writing(fixture("nmap/scan.xml"), timeout=True)
        result = run_scan(NmapScanner({"timeout": 7}), target, runner)
        assert len(result.findings) == 4
        assert result.errors == ["nmap timed out after 7s; partial results kept"]


class TestNmapScripts:
    def test_script_file_passed_after_extra_args(
        self, target: Target, tmp_path: Path
    ) -> None:
        script = tmp_path / "custom.nse"
        script.write_text("")
        scanner = NmapScanner({"nse_scripts": [str(script)]})
        cmd = scanner._build_command(target, "/tmp/out.xml")
        assert cmd[cmd.index("--script") + 1] == str(script)
        assert cmd.index("--script") < cmd.index("--")

    @pytest.mark.parametrize("name", ["missing.nse", "a,b.nse", "notes.txt"])
    def test_invalid_script_rejected(
        self, name: str, target: Target, tmp_path: Path
    ) -> None:
        (tmp_path / "notes.txt").write_text("")
        scanner = NmapScanner({"nse_scripts": [str(tmp_path / name)]})
        with pytest.raises(ExtraArgsError):
            scanner._build_command(target, "/tmp/out.xml")

    def test_adapter_returns_nse_scripts_not_extra_args(self, tmp_path: Path) -> None:
        custom = tmp_path / "nmap" / "custom"
        custom.mkdir(parents=True)
        (custom / "a.nse").write_text("")
        options = NmapTemplateAdapter().get_scanner_options(tmp_path, [])
        assert options == {"nse_scripts": [str(custom / "a.nse")]}
