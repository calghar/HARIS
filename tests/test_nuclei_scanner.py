"""Tests for the NucleiScanner adapter."""

import json

import pytest

from src.models.target import Scope, Target
from src.scanners.nuclei_scanner import DEFAULT_TEMPLATE_DIRS, NucleiScanner


@pytest.fixture
def target() -> Target:
    return Target(
        base_url="https://example.com", scope=Scope(base_url="https://example.com")
    )


class TestBuildCommand:
    def test_build_command_includes_fh2(self, target: Target) -> None:
        scanner = NucleiScanner()
        cmd = scanner._build_command(target)
        assert "-fh2" in cmd

    def test_build_command_includes_retries(self, target: Target) -> None:
        scanner = NucleiScanner()
        cmd = scanner._build_command(target)
        assert "-retries" in cmd
        assert cmd[cmd.index("-retries") + 1] == "2"

    def test_build_command_no_pt_flag(self, target: Target) -> None:
        """Protocol type filter is omitted — template dirs already scope this."""
        scanner = NucleiScanner()
        cmd = scanner._build_command(target)
        assert "-pt" not in cmd

    def test_default_template_dirs_fallback(self, target: Target) -> None:
        scanner = NucleiScanner()
        cmd = scanner._build_command(target)
        t_flags = [cmd[i + 1] for i, v in enumerate(cmd) if v == "-t"]
        for tdir in DEFAULT_TEMPLATE_DIRS:
            assert tdir in t_flags

    def test_explicit_template_dirs(self, target: Target) -> None:
        explicit = ["http/misconfiguration", "ssl"]
        scanner = NucleiScanner(options={"template_dirs": explicit})
        cmd = scanner._build_command(target)
        t_flags = [cmd[i + 1] for i, v in enumerate(cmd) if v == "-t"]
        assert "http/misconfiguration" in t_flags
        assert "ssl" in t_flags
        for tdir in DEFAULT_TEMPLATE_DIRS:
            if tdir not in explicit:
                assert tdir not in t_flags

    def test_tags_skips_default_dirs(self, target: Target) -> None:
        scanner = NucleiScanner(options={"tags": ["cve"]})
        cmd = scanner._build_command(target)
        assert "-tags" in cmd
        assert cmd[cmd.index("-tags") + 1] == "cve"
        t_flags = [cmd[i + 1] for i, v in enumerate(cmd) if v == "-t"]
        for tdir in DEFAULT_TEMPLATE_DIRS:
            assert tdir not in t_flags

    def test_templates_skips_default_dirs(self, target: Target) -> None:
        custom_path = "/path/to/custom"
        scanner = NucleiScanner(options={"templates": [custom_path]})
        cmd = scanner._build_command(target)
        t_flags = [cmd[i + 1] for i, v in enumerate(cmd) if v == "-t"]
        assert custom_path in t_flags
        for tdir in DEFAULT_TEMPLATE_DIRS:
            assert tdir not in t_flags


class TestDefaults:
    def test_default_timeout_1800(self) -> None:
        scanner = NucleiScanner()
        assert scanner.options["timeout"] == 1800

    def test_default_rate_limit_100(self) -> None:
        scanner = NucleiScanner()
        assert scanner.options["rate_limit"] == 100

    def test_nmhe_in_command(self, target: Target) -> None:
        """Host error skipping is disabled via -nmhe."""
        scanner = NucleiScanner()
        cmd = scanner._build_command(target)
        assert "-nmhe" in cmd
        assert "-mhe" not in cmd


class TestParseResults:
    def test_parse_results_basic(self, target: Target) -> None:
        raw_line = json.dumps(
            {
                "template-id": "tech-detect",
                "info": {
                    "name": "Wappalyzer Technology Detection",
                    "severity": "info",
                    "tags": ["tech"],
                },
                "matched-at": "https://example.com",
                "matcher-name": "astro",
                "ip": "1.2.3.4",
            }
        )
        scanner = NucleiScanner()
        findings = scanner.parse_results(raw_line)
        assert len(findings) == 1
        finding = findings[0]
        assert "Wappalyzer Technology Detection" in finding.title
        assert finding.url == "https://example.com"
        assert finding.scanner == "nuclei"

    def test_parse_results_empty_output(self) -> None:
        scanner = NucleiScanner()
        assert scanner.parse_results("") == []

    def test_parse_results_skips_invalid_json(self) -> None:
        scanner = NucleiScanner()
        raw = "not-json\n" + json.dumps(
            {
                "template-id": "ssl-detect",
                "info": {"name": "SSL Check", "severity": "low", "tags": ["ssl"]},
                "matched-at": "https://example.com",
            }
        )
        findings = scanner.parse_results(raw)
        assert len(findings) == 1
        assert findings[0].scanner == "nuclei"

    def test_parse_results_cve_enriches_title_and_references(self) -> None:
        raw_line = json.dumps(
            {
                "template-id": "CVE-2021-44228",
                "info": {
                    "name": "Log4Shell",
                    "severity": "critical",
                    "tags": ["cve", "rce"],
                    "classification": {
                        "cve-id": ["CVE-2021-44228"],
                        "cwe-id": ["CWE-917"],
                        "cvss-score": 10.0,
                    },
                },
                "matched-at": "https://example.com/app",
                "matcher-name": "log4j-rce",
            }
        )
        scanner = NucleiScanner()
        findings = scanner.parse_results(raw_line)
        assert len(findings) == 1
        finding = findings[0]
        assert "CVE-2021-44228" in finding.title
        assert any("nvd.nist.gov" in ref for ref in finding.references)
        assert finding.cwe_id == "CWE-917"
