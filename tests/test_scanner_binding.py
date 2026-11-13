import os
import stat
import subprocess
from collections.abc import Callable
from pathlib import Path
from typing import Any
from unittest.mock import patch

import pytest

from haris.models import ScannerResult
from haris.models.scan_context import ScanContext
from haris.models.target import Target
from haris.scanners import nuclei_scanner
from haris.scanners.base import ExternalToolScanner
from haris.scanners.nikto_scanner import NiktoScanner
from haris.scanners.nmap_scanner import NmapScanner
from haris.scanners.nuclei_scanner import NucleiScanner
from haris.scanners.sslyze_scanner import SSLyzeScanner
from haris.scanners.wapiti_scanner import WapitiScanner
from tests.conftest import PUBLIC_ADDRESS, bound_context

NMAP_XML = Path(__file__).parent / "fixtures" / "scanners" / "nmap" / "scan.xml"
HOST = "example.com"
HTTPS_URL = f"https://{HOST}"
LITERAL_URL = "https://203.0.113.5"
PROXY = bound_context().egress_proxy
TOOLS: dict[str, type[ExternalToolScanner]] = {
    "nmap": NmapScanner,
    "sslyze": SSLyzeScanner,
    "nikto": NiktoScanner,
    "nuclei": NucleiScanner,
    "wapiti": WapitiScanner,
}
REASONS = {
    "nmap": "no vetted address",
    "sslyze": "no vetted address",
    "nikto": "no egress proxy",
    "nuclei": "no egress proxy",
    "wapiti": "no egress proxy",
}
UNBOUND = {
    "nmap": {"target_ip": ""},
    "sslyze": {"target_ip": ""},
    "nikto": {"egress_proxy": ""},
    "nuclei": {"egress_proxy": ""},
    "wapiti": {"egress_proxy": ""},
}


def scanner_for(tool: str, **options: Any) -> ExternalToolScanner:
    return TOOLS[tool](options)


@pytest.fixture(autouse=True)
def nuclei_without_templates(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(NucleiScanner, "_check_templates_available", lambda _s: True)
    monkeypatch.setattr(NucleiScanner, "_template_root", lambda _s: None)


def run_scan(
    scanner: ExternalToolScanner,
    url: str,
    context: ScanContext | None,
    stdout: str = "",
    write: Callable[[list[str]], None] | None = None,
) -> tuple[ScannerResult, list[list[str]]]:
    """Scan with the process boundary faked; returns the result and every argv."""
    argvs: list[list[str]] = []

    def fake(cmd: list[str], _timeout: float) -> tuple[int, str, str]:
        argvs.append(cmd)
        if write:
            write(cmd)
        return 0, stdout, ""

    with (
        patch.object(scanner, "_check_tool_available", return_value=True),
        patch("haris.scanners.base.run_process", side_effect=fake),
    ):
        return scanner.scan(Target(base_url=url), context), argvs


def after(argv: list[str], flag: str) -> str:
    return argv[argv.index(flag) + 1]


def check_nmap(argv: list[str]) -> None:
    assert argv[-2:] == ["--", PUBLIC_ADDRESS]
    assert "-n" in argv
    assert HOST not in argv


def check_sslyze(argv: list[str]) -> None:
    assert argv[-2:] == ["--", f"{HOST}:443{{{PUBLIC_ADDRESS}}}"]


def proxy_flag(flag: str) -> Callable[[list[str]], None]:
    def check(argv: list[str]) -> None:
        assert after(argv, flag) == PROXY

    return check


BINDINGS: dict[str, Callable[[list[str]], None]] = {
    "nmap": check_nmap,
    "sslyze": check_sslyze,
    "nikto": proxy_flag("-useproxy"),
    "nuclei": proxy_flag("-proxy"),
    "wapiti": proxy_flag("--proxy"),
}


class TestBoundArgv:
    @pytest.mark.parametrize("tool", TOOLS)
    def test_argv_carries_the_binding(self, tool: str) -> None:
        result, argvs = run_scan(scanner_for(tool), HTTPS_URL, bound_context())

        assert argvs, f"{tool} never started"
        for argv in argvs:
            BINDINGS[tool](argv)
        assert not any("was not started" in e for e in result.errors)

    @pytest.mark.parametrize("tool", ["nmap", "sslyze"])
    def test_ip_literal_host_needs_no_vetted_address(self, tool: str) -> None:
        context = bound_context(target_ip="")
        _, argvs = run_scan(scanner_for(tool), LITERAL_URL, context)

        assert [argv[-1] for argv in argvs] == [
            "203.0.113.5" if tool == "nmap" else "203.0.113.5:443"
        ]

    @pytest.mark.parametrize("tool", ["nikto", "nuclei", "wapiti"])
    def test_ip_literal_host_still_needs_the_proxy(self, tool: str) -> None:
        result, argvs = run_scan(
            scanner_for(tool), LITERAL_URL, bound_context(egress_proxy="")
        )

        assert argvs == []
        assert result.errors == [f"{tool} was not started: no egress proxy"]


@pytest.fixture(scope="module")
def stub_bin(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """One stub per tool; each run appends its name to the file in $STUB_MARKER."""
    bin_dir = tmp_path_factory.mktemp("bin")
    for name in TOOLS:
        script = bin_dir / name
        script.write_text(f'#!/bin/sh\necho {name} >> "$STUB_MARKER"\n')
        script.chmod(script.stat().st_mode | stat.S_IXUSR)
        # A new file's first exec can stall for seconds on macOS.
        subprocess.run([script], check=True, env={"STUB_MARKER": os.devnull})
    return bin_dir


@pytest.fixture
def stub_dir(stub_bin: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    monkeypatch.setenv("PATH", f"{stub_bin}{os.pathsep}{os.environ['PATH']}")
    monkeypatch.setenv("STUB_MARKER", str(tmp_path / "marker"))
    return tmp_path


class TestUnboundNeverStarts:
    @pytest.mark.parametrize("missing", ["no context", "binding empty"])
    @pytest.mark.parametrize("tool", TOOLS)
    def test_stub_never_runs_and_one_error_names_tool_and_reason(
        self, tool: str, missing: str, stub_dir: Path
    ) -> None:
        context = None if missing == "no context" else bound_context(**UNBOUND[tool])
        scanner = scanner_for(tool)
        result = scanner.scan(Target(base_url=HTTPS_URL), context)

        assert not (stub_dir / "marker").exists(), f"{tool} was executed"
        assert result.errors == [f"{tool} was not started: {REASONS[tool]}"]
        assert result.findings == []

    @pytest.mark.parametrize("tool", TOOLS)
    def test_stub_runs_when_bound(self, tool: str, stub_dir: Path) -> None:
        scanner_for(tool).scan(Target(base_url=HTTPS_URL), bound_context())

        assert (stub_dir / "marker").exists(), f"{tool} stub never ran when bound"

    def test_sslyze_skip_decision_comes_before_the_binding_check(self) -> None:
        result = SSLyzeScanner().scan(Target(base_url="http://example.com"), None)

        assert result.errors == []
        assert result.metadata["status"] == "skipped"

    def test_binding_check_comes_before_the_tool_available_check(self) -> None:
        scanner = NiktoScanner()
        with patch.object(scanner, "_check_tool_available") as available:
            result = scanner.scan(Target(base_url=HTTPS_URL), None)

        available.assert_not_called()
        assert result.errors == ["nikto was not started: no egress proxy"]


class TestNmapKeepsTheHostname:
    @staticmethod
    def write_report(argv: list[str]) -> None:
        Path(after(argv, "-oX")).write_text(NMAP_XML.read_text())

    def test_findings_name_the_host_not_the_address(self) -> None:
        result, _ = run_scan(
            NmapScanner(), HTTPS_URL, bound_context(), write=self.write_report
        )

        assert result.findings
        for finding in result.findings:
            assert finding.url.startswith(f"{HOST}:")
            assert "localhost" not in finding.title + finding.description
        assert f"open on {HOST} (127.0.0.1)" in result.findings[0].description

    def test_findings_equal_a_scan_by_name(self) -> None:
        by_name = NMAP_XML.read_text().replace(
            '<hostname name="localhost" type="PTR"/>',
            f'<hostname name="{HOST}" type="user"/>',
        )
        expected = NmapScanner().parse_results(by_name)
        result, _ = run_scan(
            NmapScanner(), HTTPS_URL, bound_context(), write=self.write_report
        )

        def view(findings: list[Any]) -> list[tuple[Any, ...]]:
            return [
                (f.title, f.description, f.url, f.evidence, f.severity, f.tags)
                for f in findings
            ]

        assert view(result.findings) == view(expected)

    def test_ip_literal_host_findings_are_unchanged(self) -> None:
        result, _ = run_scan(
            NmapScanner(), "https://127.0.0.1", None, write=self.write_report
        )
        expected = NmapScanner().parse_results(NMAP_XML.read_text())

        assert [f.url for f in result.findings] == [f.url for f in expected]
        assert result.findings[0].url.startswith("localhost:")


class TestNucleiEptList:
    @staticmethod
    def types(argv: list[str]) -> list[str]:
        return after(argv, "-ept").split(",")

    def test_unproxied_and_excluded_types_each_appear_once(self) -> None:
        argv = NucleiScanner()._build_command(Target(base_url=HTTPS_URL))
        listed = self.types(argv)

        assert len(listed) == len(set(listed))
        assert {"dns", "tcp", "ssl", "websocket", "whois", "javascript"} <= set(listed)
        assert {"code", "file", "headless"} <= set(listed)

    def test_overlap_is_deduplicated_and_order_is_stable(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(
            nuclei_scanner, "get_nuclei_exclude_template_types", lambda: ["code", "tcp"]
        )
        monkeypatch.setattr(
            nuclei_scanner,
            "get_nuclei_unproxied_template_types",
            lambda: ["dns", "tcp", "ssl"],
        )
        argv = NucleiScanner()._build_command(Target(base_url=HTTPS_URL))

        assert self.types(argv) == ["code", "tcp", "dns", "ssl"]


OVERRIDES = {
    "nuclei": [
        "-proxy",
        "-p",
        "-resolvers",
        "-r",
        "-interface",
        "-i",
        "-source-ip",
        "-sip",
        "-u",
        "-l",
    ],
    "nikto": ["-useproxy", "-USEPROXY", "-host", "-Option"],
    "wapiti": ["-p", "--proxy", "--prox", "-u", "--url"],
    "sslyze": ["--https_tunnel"],
    "nmap": ["-S", "-e", "--dns-servers", "--proxies"],
}


class TestExtraArgsCannotOverrideTheBinding:
    @pytest.mark.parametrize(
        ("tool", "flag"),
        [(tool, flag) for tool, flags in OVERRIDES.items() for flag in flags],
    )
    @pytest.mark.parametrize("joined", [False, True])
    def test_flag_is_rejected_and_nothing_runs(
        self, tool: str, flag: str, joined: bool
    ) -> None:
        args = [f"{flag}=http://203.0.113.9:1"] if joined else [flag, "203.0.113.9"]
        result, argvs = run_scan(
            scanner_for(tool, extra_args=args), HTTPS_URL, bound_context()
        )

        assert argvs == []
        assert any("not allowed" in error for error in result.errors)
