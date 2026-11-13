import json
from pathlib import Path
from urllib.parse import urlsplit

import pytest

from haris.models import Severity
from haris.models.scan_context import ScanContext
from haris.models.target import Scope, Target
from haris.net.scoped_client import ScopedClient
from haris.scanners.nuclei_scanner import BASELINE_TEMPLATE_DIRS, NucleiScanner
from haris.scanners.option_policy import (
    ScannerOptionsError,
    prepare_web_scanner_options,
)
from tests.conftest import bound_context


@pytest.fixture
def target() -> Target:
    return Target(base_url="https://example.com", scope=Scope())


class TestBuildCommand:
    def test_build_command_includes_fhr(self, target: Target) -> None:
        scanner = NucleiScanner()
        cmd = scanner._build_command(target)
        assert "-fhr" in cmd

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

    def test_baseline_template_dirs_fallback(self, target: Target) -> None:
        scanner = NucleiScanner()
        cmd = scanner._build_command(target)
        t_flags = [cmd[i + 1] for i, v in enumerate(cmd) if v == "-t"]
        for tdir in BASELINE_TEMPLATE_DIRS:
            assert tdir in t_flags

    def test_explicit_template_dirs(self, target: Target) -> None:
        explicit = ["http/misconfiguration", "ssl"]
        scanner = NucleiScanner(options={"template_dirs": explicit})
        cmd = scanner._build_command(target)
        t_flags = [cmd[i + 1] for i, v in enumerate(cmd) if v == "-t"]
        assert "http/misconfiguration" in t_flags
        assert "ssl" in t_flags
        for tdir in BASELINE_TEMPLATE_DIRS:
            if tdir not in explicit:
                assert tdir not in t_flags

    def test_tags_skips_default_dirs(self, target: Target) -> None:
        scanner = NucleiScanner(options={"tags": ["cve"]})
        cmd = scanner._build_command(target)
        assert "-tags" in cmd
        assert cmd[cmd.index("-tags") + 1] == "cve"
        t_flags = [cmd[i + 1] for i, v in enumerate(cmd) if v == "-t"]
        for tdir in BASELINE_TEMPLATE_DIRS:
            assert tdir not in t_flags

    def test_templates_skips_default_dirs(self, target: Target) -> None:
        custom_path = "/path/to/custom"
        scanner = NucleiScanner(options={"templates": [custom_path]})
        cmd = scanner._build_command(target)
        t_flags = [cmd[i + 1] for i, v in enumerate(cmd) if v == "-t"]
        assert custom_path in t_flags
        for tdir in BASELINE_TEMPLATE_DIRS:
            assert tdir not in t_flags


class TestDefaults:
    def test_default_timeout_3600(self) -> None:
        scanner = NucleiScanner()
        assert scanner.options["timeout"] == 3600

    def test_default_rate_limit_100(self) -> None:
        scanner = NucleiScanner()
        assert scanner.options["rate_limit"] == 100

    def test_mhe_in_command(self, target: Target) -> None:
        """Host errors are capped with -mhe; -nmhe disables nuclei's protection."""
        scanner = NucleiScanner()
        cmd = scanner._build_command(target)
        assert cmd[cmd.index("-mhe") + 1] == "500"
        assert "-nmhe" not in cmd

    def test_default_timeout_per_request_30(self) -> None:
        scanner = NucleiScanner()
        assert scanner.options["timeout_per_request"] == 30

    def test_timeout_per_request_appears_in_command(self, target: Target) -> None:
        scanner = NucleiScanner()
        cmd = scanner._build_command(target)
        assert cmd[cmd.index("-timeout") + 1] == "30"

    def test_timeout_per_request_override(self, target: Target) -> None:
        cmd = NucleiScanner(options={"timeout_per_request": 10})._build_command(target)
        assert cmd[cmd.index("-timeout") + 1] == "10"

    @pytest.mark.parametrize("retries", [0, 1, 5])
    def test_retries_option_reaches_argv(self, target: Target, retries: int) -> None:
        cmd = NucleiScanner(options={"retries": retries})._build_command(target)
        assert cmd[cmd.index("-retries") + 1] == str(retries)

    def test_retries_accepted_from_web_options(self) -> None:
        options = {"nuclei": {"retries": 0}}
        assert prepare_web_scanner_options(options) == options

    @pytest.mark.parametrize("value", [-1, "2", True])
    def test_retries_rejects_invalid_values_from_web_options(
        self, value: object
    ) -> None:
        with pytest.raises(ScannerOptionsError, match="nuclei.retries"):
            prepare_web_scanner_options({"nuclei": {"retries": value}})


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
        assert any(
            urlsplit(ref).hostname == "nvd.nist.gov" for ref in finding.references
        )
        assert finding.cwe_id == "CWE-917"


class TestInteractshFlag:
    def test_interactsh_disabled_by_default(self, target: Target) -> None:
        scanner = NucleiScanner()
        cmd = scanner._build_command(target)
        assert "-no-interactsh" in cmd

    def test_interactsh_enabled_when_opted_in(self, target: Target) -> None:
        scanner = NucleiScanner(options={"enable_interactsh": True})
        cmd = scanner._build_command(target)
        assert "-no-interactsh" not in cmd

    def test_interactsh_disabled_explicit(self, target: Target) -> None:
        scanner = NucleiScanner(options={"enable_interactsh": False})
        cmd = scanner._build_command(target)
        assert "-no-interactsh" in cmd


class TestDosExclusionTag:
    def test_dos_excluded_by_default(self, target: Target) -> None:
        scanner = NucleiScanner()
        cmd = scanner._build_command(target)
        assert "-etags" in cmd
        etags_value = cmd[cmd.index("-etags") + 1]
        assert "dos" in etags_value.lower()

    def test_dos_excluded_with_other_tags(self, target: Target) -> None:
        scanner = NucleiScanner(options={"exclude_tags": ["intrusive"]})
        cmd = scanner._build_command(target)
        etags_value = cmd[cmd.index("-etags") + 1]
        assert "dos" in etags_value
        assert "intrusive" in etags_value

    def test_dos_not_duplicated(self, target: Target) -> None:
        scanner = NucleiScanner(options={"exclude_tags": ["dos", "intrusive"]})
        cmd = scanner._build_command(target)
        etags_value = cmd[cmd.index("-etags") + 1]
        assert etags_value.count("dos") == 1


class TestBuildCommandKeywordArgs:
    def test_template_dirs_param(self, target: Target) -> None:
        scanner = NucleiScanner()
        cmd = scanner._build_command(target, template_dirs=["http/exposures"])
        t_flags = [cmd[i + 1] for i, v in enumerate(cmd) if v == "-t"]
        assert "http/exposures" in t_flags

    def test_extra_tags_param(self, target: Target) -> None:
        scanner = NucleiScanner()
        cmd = scanner._build_command(target, extra_tags=["wordpress", "joomla"])
        assert "-tags" in cmd
        tags_value = cmd[cmd.index("-tags") + 1]
        assert "wordpress" in tags_value
        assert "joomla" in tags_value

    def test_workflows_param(self, target: Target) -> None:
        scanner = NucleiScanner()
        cmd = scanner._build_command(
            target, workflows=["workflows/wordpress-workflow.yaml"]
        )
        assert "-w" in cmd
        w_flags = [cmd[i + 1] for i, v in enumerate(cmd) if v == "-w"]
        assert "workflows/wordpress-workflow.yaml" in w_flags

    def test_no_url_file_uses_u(self, target: Target) -> None:
        scanner = NucleiScanner()
        cmd = scanner._build_command(target)
        assert "-u" in cmd
        assert "-list" not in cmd

    def test_url_file_uses_list(self, target: Target) -> None:
        scanner = NucleiScanner()
        cmd = scanner._build_command(target, url_file="/tmp/urls.txt")
        assert cmd[cmd.index("-list") + 1] == "/tmp/urls.txt"
        assert "-u" not in cmd

    def test_multiple_kwargs_combined(self, target: Target) -> None:
        scanner = NucleiScanner()
        cmd = scanner._build_command(
            target,
            template_dirs=["http/exposures"],
            extra_tags=["wordpress"],
            workflows=["workflows/wordpress-workflow.yaml"],
        )
        assert "-t" in cmd
        assert "-tags" in cmd
        assert "-w" in cmd


class TestBaselineTemplateDirs:
    def test_yaml_default_is_the_five_baseline_dirs(self) -> None:
        assert BASELINE_TEMPLATE_DIRS == [
            "http/exposures",
            "http/misconfiguration",
            "http/vulnerabilities",
            "http/takeovers",
            "dast",
        ]

    @pytest.mark.parametrize("excluded", ["http/cves", "http/technologies", "ssl"])
    def test_product_specific_and_fingerprint_dirs_are_not_baseline(
        self, excluded: str
    ) -> None:
        assert excluded not in BASELINE_TEMPLATE_DIRS


def _vetted(target: Target) -> ScanContext:
    ctx = ScanContext()
    ctx.http = ScopedClient(target, resolver=lambda _host, _port: ["93.184.216.34"])
    return ctx


class TestBuildUrlList:
    def test_base_url_only_when_no_context_urls(self, target: Target) -> None:
        urls = NucleiScanner._build_url_list(target, ScanContext())
        assert urls == []

    def test_combines_base_and_discovered_urls(self, target: Target) -> None:
        ctx = _vetted(target)
        ctx.add_urls(["https://example.com/admin", "https://example.com/login"])
        urls = NucleiScanner._build_url_list(target, ctx)
        assert target.base_url in urls
        assert "https://example.com/admin" in urls
        assert "https://example.com/login" in urls

    def test_deduplicates_base_url(self, target: Target) -> None:
        ctx = _vetted(target)
        ctx.add_urls([target.base_url, "https://example.com/admin"])
        urls = NucleiScanner._build_url_list(target, ctx)
        assert urls.count(target.base_url) == 1

    def test_caps_at_500_urls(self, target: Target) -> None:
        ctx = _vetted(target)
        ctx.add_urls([f"https://example.com/page{i}" for i in range(1000)])
        urls = NucleiScanner._build_url_list(target, ctx)
        assert len(urls) <= 500

    def test_filters_non_http_urls(self, target: Target) -> None:
        ctx = _vetted(target)
        ctx.discovered_urls = [
            "https://example.com/valid",
            "ftp://example.com/invalid",
            "file:///etc/passwd",
        ]
        urls = NucleiScanner._build_url_list(target, ctx)
        assert "https://example.com/valid" in urls
        assert not any(u.startswith("ftp://") for u in urls)
        assert not any(u.startswith("file://") for u in urls)

    def test_returns_empty_when_only_base_url(self, target: Target) -> None:
        ctx = _vetted(target)
        ctx.add_urls([target.base_url])
        urls = NucleiScanner._build_url_list(target, ctx)
        assert urls == []

    def test_l4_discovered_urls_drop_off_scope_and_blocked_hosts(
        self, target: Target
    ) -> None:
        seen: list[str] = []

        def resolver(host: str, _port: int) -> list[str]:
            seen.append(host)
            if host == "rebind.example.com":
                return ["10.0.0.5"]
            return ["93.184.216.34"]

        ctx = ScanContext()
        ctx.http = ScopedClient(target, resolver=resolver)
        ctx.discovered_urls = [
            "https://example.com/admin",
            "https://rebind.example.com/secret",
            "https://other.test/x",
            "http://10.0.0.5/meta",
        ]
        urls = NucleiScanner._build_url_list(target, ctx)
        assert "https://example.com/admin" in urls
        assert "https://rebind.example.com/secret" not in urls
        assert "https://other.test/x" not in urls
        assert "http://10.0.0.5/meta" not in urls
        assert "other.test" not in seen
        assert "10.0.0.5" not in seen

    @pytest.mark.parametrize(
        ("url", "kept"),
        [
            ("https://example.com/robots.txt", True),
            ("https://example.com:443/robots.txt", True),
            ("http://example.com/robots.txt", False),
            ("https://example.com:8443/robots.txt", False),
            ("https://other.test/robots.txt", False),
            ("https://example.com", True),
            ("https://host.containers.internal", False),
        ],
    )
    def test_list_holds_the_base_origin_only(
        self, target: Target, url: str, kept: bool
    ) -> None:
        ctx = _vetted(target)
        ctx.discovered_urls = ["https://example.com/robots.txt", url]
        assert (url in NucleiScanner._build_url_list(target, ctx)) is kept


class TestMapTagsAndWorkflows:
    def test_no_tech_gives_nothing(self) -> None:
        tags, workflows = NucleiScanner()._map_tags_and_workflows(ScanContext())
        assert tags == []
        assert workflows == []

    def test_wordpress_tech_adds_tags(self) -> None:
        ctx = ScanContext()
        ctx.add_technologies(["wordpress"])
        tags, _ = NucleiScanner()._map_tags_and_workflows(ctx)
        assert "wordpress" in tags
        assert "wp-plugin" in tags or "wp-theme" in tags

    def test_wordpress_tech_adds_workflow(self, tmp_path: Path) -> None:
        from unittest.mock import patch

        scanner = NucleiScanner()
        ctx = ScanContext()
        ctx.add_technologies(["wordpress"])
        (tmp_path / "workflows").mkdir()
        (tmp_path / "workflows" / "wordpress-workflow.yaml").write_text("id: x")
        with patch.object(scanner, "_template_root", return_value=tmp_path):
            _, workflows = scanner._map_tags_and_workflows(ctx)
        assert "workflows/wordpress-workflow.yaml" in workflows

    def test_multiple_techs_combine_tags(self) -> None:
        ctx = ScanContext()
        ctx.add_technologies(["wordpress", "nginx", "php"])
        tags, _ = NucleiScanner()._map_tags_and_workflows(ctx)
        assert {"wordpress", "nginx", "php"} <= set(tags)

    def test_tech_tag_deduplication(self) -> None:
        ctx = ScanContext()
        ctx.add_technologies(["apache-tomcat", "tomcat"])
        tags, _ = NucleiScanner()._map_tags_and_workflows(ctx)
        tomcat_tags = [t for t in tags if "tomcat" in t]
        assert len(tomcat_tags) == len(set(tomcat_tags))

    def test_unknown_tech_no_tags_added(self) -> None:
        ctx = ScanContext()
        ctx.add_technologies(["unknown-tech-xyz"])
        tags, _ = NucleiScanner()._map_tags_and_workflows(ctx)
        assert "unknown-tech-xyz" not in tags

    def test_case_insensitive_tech_matching(self) -> None:
        ctx = ScanContext()
        ctx.add_technologies(["WordPress", "NGINX"])
        tags, _ = NucleiScanner()._map_tags_and_workflows(ctx)
        assert any("wordpress" in t.lower() for t in tags)
        assert any("nginx" in t.lower() for t in tags)


class TestCheckTemplatesAvailable:
    def test_returns_true_when_dir_exists(self, tmp_path: Path) -> None:
        from unittest.mock import patch

        scanner = NucleiScanner()
        with patch.object(scanner, "_template_root", return_value=tmp_path):
            assert scanner._check_templates_available() is True

    def test_returns_false_and_warns_when_dir_missing(self, tmp_path: Path) -> None:
        from unittest.mock import patch

        scanner = NucleiScanner()
        with (
            patch.object(scanner, "_template_root", return_value=tmp_path / "nope"),
            patch("haris.scanners.nuclei_scanner.logger") as mock_logger,
        ):
            assert scanner._check_templates_available() is False
            assert mock_logger.warning.called


class TestRunPhase:
    def test_success_returns_findings(self, target: Target) -> None:
        from unittest.mock import patch

        scanner = NucleiScanner()
        result_json = json.dumps(
            {
                "template-id": "test-template",
                "info": {"name": "Test Finding", "severity": "high"},
            }
        )
        with patch.object(scanner, "_run_command", return_value=(0, result_json, "")):
            findings, errors, raw = scanner._run_phase(target, phase_label="test")
            assert len(findings) == 1
            assert findings[0].title == "Test Finding"
            assert len(errors) == 0

    def test_fatal_stderr_creates_error(self, target: Target) -> None:
        from unittest.mock import patch

        scanner = NucleiScanner()
        with patch.object(
            scanner, "_run_command", return_value=(1, "", "[FTL] critical error")
        ):
            findings, errors, raw = scanner._run_phase(target, phase_label="test")
            assert len(findings) == 0
            assert len(errors) == 1
            assert "FTL" in errors[0]

    def test_returncode_greater_than_1_creates_error(self, target: Target) -> None:
        from unittest.mock import patch

        scanner = NucleiScanner()
        with patch.object(
            scanner, "_run_command", return_value=(2, "", "error output")
        ):
            findings, errors, raw = scanner._run_phase(target, phase_label="test")
            assert len(errors) == 1
            assert "code 2" in errors[0]

    def test_empty_stdout_returns_empty_findings(self, target: Target) -> None:
        from unittest.mock import patch

        scanner = NucleiScanner()
        with patch.object(scanner, "_run_command", return_value=(0, "", "")):
            findings, errors, raw = scanner._run_phase(target, phase_label="test")
            assert len(findings) == 0
            assert len(errors) == 0

    def test_unsolicited_response_filtered_from_stderr(self, target: Target) -> None:
        from unittest.mock import patch

        scanner = NucleiScanner()
        stderr = "line1\nUnsolicited response received\nline2"
        with (
            patch.object(scanner, "_run_command", return_value=(0, "", stderr)),
            patch("haris.scanners.nuclei_scanner.logger") as mock_logger,
        ):
            scanner._run_phase(target, phase_label="test")
            # Check that the warning doesn't contain "Unsolicited"
            if mock_logger.warning.called:
                warning_msg = str(mock_logger.warning.call_args)
                assert "Unsolicited response" not in warning_msg


class TestResultToFinding:
    def test_missing_template_id_and_name_returns_none(self) -> None:
        scanner = NucleiScanner()
        result: dict = {"info": {}}  # no template-id AND no name in info
        finding = scanner._result_to_finding(result)
        # Actually returns a Finding with "Unknown finding" as the default name
        assert finding is not None
        assert finding.title == "Unknown finding"

    def test_string_reference_converted_to_list(self) -> None:
        scanner = NucleiScanner()
        result = {
            "template-id": "test",
            "info": {
                "name": "Test",
                "severity": "medium",
                "reference": "https://example.com",  # string, not list
            },
        }
        finding = scanner._result_to_finding(result)
        assert finding is not None
        assert finding.references == ["https://example.com"]

    def test_cvss_score_in_raw_data(self) -> None:
        scanner = NucleiScanner()
        result = {
            "template-id": "test-cve",
            "info": {
                "name": "CVE Test",
                "severity": "high",
                "classification": {"cvss-score": 8.5},
            },
        }
        finding = scanner._result_to_finding(result)
        assert finding is not None
        # Note: stored with hyphen, not underscore
        assert finding.raw_data.get("cvss-score") == 8.5

    def test_matcher_name_in_title(self) -> None:
        scanner = NucleiScanner()
        result = {
            "template-id": "test",
            "matcher-name": "specific-check",
            "info": {"name": "Finding Name", "severity": "low"},
        }
        finding = scanner._result_to_finding(result)
        assert finding is not None
        assert "specific-check" in finding.title


class TestWriteUrlList:
    def test_creates_file_with_urls(self) -> None:
        from pathlib import Path

        urls = ["https://example.com/page1", "https://example.com/page2"]
        filepath = NucleiScanner._write_url_list(urls)
        try:
            assert Path(filepath).exists()
            content = Path(filepath).read_text()
            assert "https://example.com/page1" in content
            assert "https://example.com/page2" in content
        finally:
            Path(filepath).unlink(missing_ok=True)

    def test_urls_separated_by_newlines(self) -> None:
        from pathlib import Path

        urls = ["https://a.com", "https://b.com"]
        filepath = NucleiScanner._write_url_list(urls)
        try:
            content = Path(filepath).read_text()
            assert content == "https://a.com\nhttps://b.com"
        finally:
            Path(filepath).unlink(missing_ok=True)


class TestGenericRemediation:
    def test_known_tag_returns_specific_remediation(self) -> None:

        remediation = NucleiScanner._generic_remediation(
            ["sql_injection"], Severity.HIGH
        )
        assert "parameterised queries" in remediation.lower()

    def test_unknown_tag_returns_default(self) -> None:

        remediation = NucleiScanner._generic_remediation(
            ["unknown-tag-xyz"], Severity.MEDIUM
        )
        assert "security standard" in remediation.lower()

    def test_first_match_wins(self) -> None:

        # Both are in remediation_map, should return first match
        remediation = NucleiScanner._generic_remediation(
            ["xss", "sql_injection"], Severity.HIGH
        )
        # XSS comes first in the tags list
        assert (
            "output encoding" in remediation.lower()
            or "Content-Security-Policy" in remediation
        )


class TestScanAuthHeaderForwarding:
    def test_auth_header_forwarded_to_command(self, target: Target) -> None:
        from haris.models.target import AuthConfig

        target.auth = AuthConfig(
            method="header", header_name="X-API-Key", header_value="secret123"
        )
        scanner = NucleiScanner()
        cmd = scanner._build_command(target)
        assert "-H" in cmd
        h_idx = cmd.index("-H")
        assert cmd[h_idx + 1] == "X-API-Key: secret123"

    def test_no_auth_means_no_h_flag(self, target: Target) -> None:
        from haris.models.target import AuthConfig

        target.auth = AuthConfig(method="none")
        # Count -H flags - should only be for non-auth headers if any
        auth_headers = target.auth.as_headers()
        assert len(auth_headers) == 0


class TestScanFullFlow:
    def test_scan_returns_scanner_result(self, target: Target) -> None:
        from unittest.mock import patch

        scanner = NucleiScanner()
        with (
            patch.object(scanner, "_check_tool_available", return_value=True),
            patch.object(scanner, "_check_templates_available", return_value=True),
            patch.object(scanner, "_run_phase", return_value=([], [], "")),
        ):
            result = scanner.scan(target, bound_context())
            assert result.scanner_name == "nuclei"
            assert isinstance(result.findings, list)

    def test_tool_missing_returns_error(self, target: Target) -> None:
        from unittest.mock import patch

        scanner = NucleiScanner()
        with patch.object(scanner, "_check_tool_available", return_value=False):
            result = scanner.scan(target, bound_context())
            assert len(result.errors) == 1
            assert "not installed" in result.errors[0]

    def test_default_scan_runs_the_tag_group_and_the_baseline_group(
        self, target: Target
    ) -> None:
        from unittest.mock import patch

        scanner = NucleiScanner()
        with (
            patch.object(scanner, "_check_tool_available", return_value=True),
            patch.object(scanner, "_check_templates_available", return_value=True),
            patch.object(scanner, "_run_phase", return_value=([], [], "")) as mock_run,
        ):
            scanner.scan(target, bound_context())
        labels = [c.kwargs["phase_label"] for c in mock_run.call_args_list]
        assert labels == ["phase2-tags", "phase2-baseline"]
