"""Nuclei multi-phase orchestration, command flags, template root, redaction.

Fixtures are real nuclei 3.7.1 output; see tests/fixtures/scanners/README.md.
"""

import json
from pathlib import Path
from typing import Any
from unittest.mock import patch

import pytest

from haris.models.scan_context import ScanContext
from haris.models.target import AuthConfig, Scope, Target
from haris.scanners.nuclei_scanner import (
    DEFAULT_TEMPLATE_DIRS,
    TECH_FINGERPRINT_DIR,
    NucleiScanner,
)
from haris.scanners.nuclei_templates import config_dir_from, templates_dir_from
from haris.scanners.process import ToolTimeoutError
from tests.conftest import bound_context

FIXTURES = Path(__file__).parent / "fixtures" / "scanners" / "nuclei"
SECRETS = ("nuclei-secret-token", "nuclei-secret-key", "nuclei-secret-cookie")


def fixture(name: str) -> str:
    return (FIXTURES / name).read_text()


class FakeNuclei:
    """Fake ``run_process``: answers by phase, records every argv."""

    def __init__(
        self,
        tech: str = "",
        broad: str = "",
        targeted: str = "",
        raises: dict[str, ToolTimeoutError] | None = None,
    ) -> None:
        self.calls: list[list[str]] = []
        self.answers = {"tech": tech, "broad": broad, "targeted": targeted}
        self.raises = raises or {}

    @staticmethod
    def phase(cmd: list[str]) -> str:
        if "-version" in cmd or "-ut" in cmd:
            return "meta"
        if TECH_FINGERPRINT_DIR in cmd:
            return "tech"
        return "targeted" if "-et" in cmd else "broad"

    def __call__(self, cmd: list[str], _timeout: float) -> tuple[int, str, str]:
        self.calls.append(cmd)
        phase = self.phase(cmd)
        if phase in self.raises:
            raise self.raises[phase]
        return 0, self.answers.get(phase, ""), ""

    def phase_calls(self, phase: str) -> list[list[str]]:
        return [c for c in self.calls if self.phase(c) == phase]


@pytest.fixture
def target() -> Target:
    return Target(base_url="http://127.0.0.1:18080", scope=Scope())


def scan(
    fake: FakeNuclei,
    target: Target,
    options: dict[str, Any] | None = None,
    context: ScanContext | None = None,
) -> Any:
    scanner = NucleiScanner(options)
    with (
        patch.object(scanner, "_check_tool_available", return_value=True),
        patch.object(scanner, "_check_templates_available", return_value=True),
        patch.object(scanner, "_template_root", return_value=None),
        patch("haris.scanners.base.run_process", side_effect=fake),
    ):
        return scanner.scan(target, context or bound_context())


def flag_value(cmd: list[str], flag: str) -> str:
    return cmd[cmd.index(flag) + 1]


class TestPhaseOne:
    def test_technologies_reported_not_findings(self, target: Target) -> None:
        ctx = bound_context()
        result = scan(FakeNuclei(tech=fixture("phase1_tech.jsonl")), target, None, ctx)
        assert result.findings == []
        assert result.metadata["technologies"] == ["apache", "php"]
        assert {"apache", "php"} <= set(ctx.detected_technologies)

    def test_severity_filter_does_not_apply(self, target: Target) -> None:
        scanner = NucleiScanner({"severity": ["high", "critical"]})
        cmd = scanner._build_command(
            target, template_dirs=[TECH_FINGERPRINT_DIR], phase_one=True
        )
        assert "-severity" not in cmd
        assert "-es" not in cmd

    def test_later_phases_honour_severity_filter(self, target: Target) -> None:
        scanner = NucleiScanner({"severity": ["high", "critical"]})
        cmd = scanner._build_command(target, template_dirs=["http/cves"])
        assert flag_value(cmd, "-severity") == "high,critical"
        assert "-es" not in cmd


class TestCommandFlags:
    def test_nuclei_3_flags(self, target: Target) -> None:
        cmd = NucleiScanner()._build_command(target, template_dirs=["http/cves"])
        assert "-or" in cmd
        assert "-ot" in cmd
        assert "-duc" in cmd
        assert flag_value(cmd, "-es") == "info"
        assert flag_value(cmd, "-ept") == (
            "code,file,headless,dns,tcp,ssl,websocket,whois,javascript"
        )
        assert flag_value(cmd, "-mhe") == "500"
        assert "-nmhe" not in cmd

    def test_missing_header_template_excluded(self, target: Target) -> None:
        cmd = NucleiScanner()._build_command(target, template_dirs=["http/cves"])
        assert flag_value(cmd, "-eid") == "http-missing-security-headers"

    def test_automatic_scan_flag_only_when_requested(self, target: Target) -> None:
        scanner = NucleiScanner()
        assert "-as" not in scanner._build_command(target)
        assert "-as" in scanner._build_command(target, automatic=True)

    def test_extra_args_validated(self, target: Target) -> None:
        scanner = NucleiScanner({"extra_args": ["-fr"]})
        assert "-fr" in scanner._build_command(target)


class TestPhaseTwo:
    def test_targeted_phase_excludes_broad_dirs(self, target: Target) -> None:
        fake = FakeNuclei(tech=fixture("phase1_tech.jsonl"))
        scan(fake, target)
        (broad,) = fake.phase_calls("broad")
        (targeted,) = fake.phase_calls("targeted")
        assert [broad[i + 1] for i, v in enumerate(broad) if v == "-t"] == list(
            DEFAULT_TEMPLATE_DIRS
        )
        assert flag_value(targeted, "-et") == ",".join(DEFAULT_TEMPLATE_DIRS)
        assert "-t" not in targeted
        assert "apache" in flag_value(targeted, "-tags")

    def test_same_match_in_both_phases_reported_once(self, target: Target) -> None:
        phase2 = fixture("phase2_scan.jsonl")
        fake = FakeNuclei(
            tech=fixture("phase1_tech.jsonl"), broad=phase2, targeted=phase2
        )
        result = scan(fake, target)
        assert len(result.findings) == 2

    def test_explicit_tags_run_once_without_targeted_phase(
        self, target: Target
    ) -> None:
        fake = FakeNuclei()
        scan(fake, target, {"tags": ["cve", "rce"]})
        assert len(fake.phase_calls("tech")) == 0
        assert len(fake.phase_calls("targeted")) == 0
        (broad,) = fake.phase_calls("broad")
        assert broad.count("-tags") == 1
        assert flag_value(broad, "-tags") == "cve,rce"

    def test_no_targeted_phase_without_technologies(self, target: Target) -> None:
        fake = FakeNuclei()
        scan(fake, target)
        assert fake.phase_calls("targeted") == []

    def test_automatic_scan_targets_uncovered_templates(self, target: Target) -> None:
        fake = FakeNuclei()
        scan(fake, target, {"automatic_scan": True})
        (targeted,) = fake.phase_calls("targeted")
        assert "-as" in targeted
        assert flag_value(targeted, "-et") == ",".join(DEFAULT_TEMPLATE_DIRS)

    def test_template_update_is_opt_in(self, target: Target) -> None:
        fake = FakeNuclei()
        scan(fake, target)
        assert not any("-ut" in c for c in fake.calls)
        scan(fake, target, {"update_templates": True})
        assert any("-ut" in c for c in fake.calls)


class TestTimeout:
    def test_earlier_phase_findings_survive_later_timeout(self, target: Target) -> None:
        fake = FakeNuclei(
            tech=fixture("phase1_tech.jsonl"),
            broad=fixture("phase2_scan.jsonl"),
            raises={"targeted": ToolTimeoutError("t", "", "")},
        )
        result = scan(fake, target, {"timeout": 9})
        assert len(result.findings) == 2
        assert result.errors == [
            "nuclei [phase2-targeted] timed out after 9s; partial results kept"
        ]
        assert result.metadata["technologies"] == ["apache", "php"]

    def test_partial_stdout_of_timed_out_phase_is_parsed(self, target: Target) -> None:
        fake = FakeNuclei(
            raises={"broad": ToolTimeoutError("t", fixture("phase2_scan.jsonl"), "")}
        )
        result = scan(fake, target)
        assert len(result.findings) == 2
        assert result.errors == []
        assert result.status == "partial"


class TestUrlListCleanup:
    URLS = ["http://h/a", "http://h/b", "http://h/c"]

    def test_list_file_removed_after_run(self, target: Target) -> None:
        seen: list[str] = []

        def run(cmd: list[str], _timeout: float) -> tuple[int, str, str]:
            seen.append(flag_value(cmd, "-list"))
            assert Path(seen[0]).read_text().splitlines() == self.URLS
            return 0, "", ""

        scanner = NucleiScanner()
        with patch("haris.scanners.base.run_process", side_effect=run):
            scanner._run_phase(target, url_list=self.URLS, phase_label="t")
        assert not Path(seen[0]).exists()

    def test_list_file_removed_when_tool_fails(self, target: Target) -> None:
        seen: list[str] = []

        def run(cmd: list[str], _timeout: float) -> tuple[int, str, str]:
            seen.append(flag_value(cmd, "-list"))
            raise OSError("boom")

        scanner = NucleiScanner()
        with (
            patch("haris.scanners.base.run_process", side_effect=run),
            pytest.raises(OSError, match="boom"),
        ):
            scanner._run_phase(target, url_list=self.URLS, phase_label="t")
        assert not Path(seen[0]).exists()


class TestTemplateRoot:
    def test_golden_version_and_config_output(self) -> None:
        config_dir = config_dir_from(fixture("version.txt"))
        assert config_dir == Path("/home/user/.config/nuclei")
        assert templates_dir_from(fixture("templates-config.json")) == Path(
            "/home/user/nuclei-templates"
        )

    def test_unparseable_inputs_give_none(self) -> None:
        assert config_dir_from("no such line") is None
        assert templates_dir_from("not json") is None
        assert templates_dir_from("[]") is None
        assert templates_dir_from('{"nuclei-templates-directory": ""}') is None

    def test_root_resolved_from_nuclei_config(self, tmp_path: Path) -> None:
        templates = tmp_path / "tpl"
        templates.mkdir()
        (tmp_path / ".templates-config.json").write_text(
            json.dumps({"nuclei-templates-directory": str(templates)})
        )
        version = f"[INF] Nuclei Config Directory: {tmp_path}\n"
        scanner = NucleiScanner()
        with patch("haris.scanners.base.run_process", return_value=(0, version, "")):
            assert scanner._template_root() == templates
            assert scanner._check_templates_available() is True

    def test_missing_binary_means_no_root_and_no_hardcoded_path(self) -> None:
        scanner = NucleiScanner()
        with patch("haris.scanners.base.run_process", side_effect=FileNotFoundError):
            assert scanner._template_root() is None
            assert scanner._check_templates_available() is False


class TestGoldenParsing:
    def test_phase2_findings(self) -> None:
        findings = NucleiScanner().parse_results(fixture("phase2_scan.jsonl"))
        by_title = {f.title: f for f in findings}
        assert by_title["Fixture reflected XSS"].tags == ["xss"]
        assert by_title["Fixture reflected XSS"].url.startswith("http://127.0.0.1")
        assert by_title["Fixture exposed phpinfo"].tags == ["sensitive_data_exposure"]

    def test_missing_header_template_dropped(self) -> None:
        raw = fixture("auth_raw.jsonl")
        assert "http-missing-security-headers" in raw
        ids = {f.raw_data["template-id"] for f in NucleiScanner().parse_results(raw)}
        assert "http-missing-security-headers" not in ids

    def test_curl_command_used_when_request_omitted(self) -> None:
        finding = NucleiScanner().parse_results(fixture("phase2_scan.jsonl"))[0]
        assert finding.request_example.startswith("curl ")


class TestRedaction:
    def test_secrets_absent_everywhere(
        self, target: Target, caplog: pytest.LogCaptureFixture
    ) -> None:
        target.auth = AuthConfig(
            method="header",
            header_name="Authorization",
            header_value="Bearer nuclei-secret-token",
        )
        fake = FakeNuclei(broad=fixture("auth_raw.jsonl"))
        with caplog.at_level("DEBUG"):
            result = scan(fake, target, {"skip_tech_detection": True})
        dump = result.model_dump_json() + caplog.text
        assert result.findings
        assert any(f.request_example for f in result.findings)
        for secret in SECRETS:
            assert secret not in dump

    def test_raw_request_headers_redacted_without_configured_auth(self) -> None:
        findings = NucleiScanner().parse_results(fixture("auth_raw.jsonl"))
        dump = "".join(f.model_dump_json() for f in findings)
        assert all(secret in fixture("auth_raw.jsonl") for secret in SECRETS)
        for secret in SECRETS:
            assert secret not in dump
