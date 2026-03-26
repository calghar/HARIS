"""Tests for the NucleiScanner adapter."""

import json

import pytest

from src.models import Finding, Severity
from src.models.scan_context import ScanContext
from src.models.target import Scope, Target
from src.scanners.nuclei_scanner import (
    DEFAULT_TEMPLATE_DIRS,
    TECH_FINGERPRINT_DIR,
    NucleiScanner,
)


@pytest.fixture
def target() -> Target:
    return Target(
        base_url="https://example.com", scope=Scope(base_url="https://example.com")
    )


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
    def test_default_timeout_3600(self) -> None:
        scanner = NucleiScanner()
        assert scanner.options["timeout"] == 3600

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

    def test_url_list_param_single_url(self, target: Target) -> None:
        scanner = NucleiScanner()
        cmd = scanner._build_command(target, url_list=[target.base_url])
        assert "-u" in cmd
        assert "-list" not in cmd

    def test_url_list_param_multiple_urls(self, target: Target) -> None:
        scanner = NucleiScanner()
        urls = [
            "https://example.com",
            "https://example.com/page1",
            "https://example.com/page2",
        ]
        cmd = scanner._build_command(target, url_list=urls)
        assert "-list" in cmd
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


class TestDefaultTemplateDirs:
    def test_includes_misconfiguration_dir(self) -> None:
        assert "http/misconfiguration" in DEFAULT_TEMPLATE_DIRS

    def test_includes_cves_dir(self) -> None:
        assert "http/cves" in DEFAULT_TEMPLATE_DIRS

    def test_excludes_ssl_by_default(self) -> None:
        assert "ssl" not in DEFAULT_TEMPLATE_DIRS

    def test_excludes_tech_fingerprint_dir(self) -> None:
        assert TECH_FINGERPRINT_DIR not in DEFAULT_TEMPLATE_DIRS
        assert "http/technologies" not in DEFAULT_TEMPLATE_DIRS


class TestExtractTechnologies:
    def test_extract_from_matcher_name(self) -> None:
        findings = [
            Finding(
                title="Tech Detection",
                description="",
                severity=Severity.INFO,
                raw_data={"matcher-name": "nginx"},
            )
        ]
        techs = NucleiScanner._extract_technologies(findings)
        assert "nginx" in techs

    def test_extract_multiple_techs(self) -> None:
        findings = [
            Finding(
                title="Tech 1",
                description="",
                severity=Severity.INFO,
                raw_data={"matcher-name": "nginx"},
            ),
            Finding(
                title="Tech 2",
                description="",
                severity=Severity.INFO,
                raw_data={"matcher-name": "wordpress"},
            ),
        ]
        techs = NucleiScanner._extract_technologies(findings)
        assert "nginx" in techs
        assert "wordpress" in techs

    def test_extract_from_nuclei_tags(self) -> None:
        findings = [
            Finding(
                title="Tech Detection",
                description="",
                severity=Severity.INFO,
                raw_data={"nuclei-tags": ["php", "apache"]},
            )
        ]
        techs = NucleiScanner._extract_technologies(findings)
        assert "php" in techs
        assert "apache" in techs

    def test_deduplicate_techs(self) -> None:
        findings = [
            Finding(
                title="Tech 1",
                description="",
                severity=Severity.INFO,
                raw_data={"matcher-name": "nginx"},
            ),
            Finding(
                title="Tech 2",
                description="",
                severity=Severity.INFO,
                raw_data={"matcher-name": "nginx"},
            ),
        ]
        techs = NucleiScanner._extract_technologies(findings)
        assert techs.count("nginx") == 1

    def test_skip_tech_tag_itself(self) -> None:
        findings = [
            Finding(
                title="Tech Detection",
                description="",
                severity=Severity.INFO,
                raw_data={"nuclei-tags": ["tech", "nginx"]},
            )
        ]
        techs = NucleiScanner._extract_technologies(findings)
        assert "tech" not in techs
        assert "nginx" in techs

    def test_skip_all_meta_tags(self) -> None:
        """Generic Nuclei classification tags should be filtered out."""
        findings = [
            Finding(
                title="WAF Detection",
                description="",
                severity=Severity.INFO,
                raw_data={
                    "matcher-name": "cloudflare",
                    "nuclei-tags": ["waf", "tech", "misc", "discovery", "cms"],
                },
            )
        ]
        techs = NucleiScanner._extract_technologies(findings)
        assert "cloudflare" in techs
        for meta in ("waf", "tech", "misc", "discovery", "cms"):
            assert meta not in techs

    def test_extract_from_extracted_results(self) -> None:
        """metatag-cms and similar use extracted-results for the actual tech."""
        findings = [
            Finding(
                title="Metatag CMS Detection",
                description="",
                severity=Severity.INFO,
                raw_data={
                    "matcher-name": "",
                    "extracted-results": ["Astro v5.15.9"],
                    "nuclei-tags": ["tech", "cms", "discovery"],
                },
            )
        ]
        techs = NucleiScanner._extract_technologies(findings)
        assert "astro" in techs
        assert "tech" not in techs
        assert "cms" not in techs

    def test_empty_findings_returns_empty(self) -> None:
        techs = NucleiScanner._extract_technologies([])
        assert techs == []

    def test_no_raw_data_returns_empty(self) -> None:
        findings = [
            Finding(
                title="No raw data",
                description="",
                severity=Severity.INFO,
            )
        ]
        techs = NucleiScanner._extract_technologies(findings)
        assert techs == []


class TestBuildUrlList:
    def test_base_url_only_when_no_context_urls(self, target: Target) -> None:
        ctx = ScanContext()
        urls = NucleiScanner._build_url_list(target, ctx)
        assert urls == []

    def test_combines_base_and_discovered_urls(self, target: Target) -> None:
        ctx = ScanContext()
        ctx.add_urls(["https://example.com/admin", "https://example.com/login"])
        urls = NucleiScanner._build_url_list(target, ctx)
        assert target.base_url in urls
        assert "https://example.com/admin" in urls
        assert "https://example.com/login" in urls

    def test_deduplicates_base_url(self, target: Target) -> None:
        ctx = ScanContext()
        ctx.add_urls([target.base_url, "https://example.com/admin"])
        urls = NucleiScanner._build_url_list(target, ctx)
        assert urls.count(target.base_url) == 1

    def test_caps_at_500_urls(self, target: Target) -> None:
        ctx = ScanContext()
        ctx.add_urls([f"https://example.com/page{i}" for i in range(1000)])
        urls = NucleiScanner._build_url_list(target, ctx)
        assert len(urls) <= 500

    def test_filters_non_http_urls(self, target: Target) -> None:
        ctx = ScanContext()
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
        ctx = ScanContext()
        ctx.add_urls([target.base_url])
        urls = NucleiScanner._build_url_list(target, ctx)
        assert urls == []


class TestResolveTargetedSelection:
    def test_explicit_template_dirs_returned_as_is(self, target: Target) -> None:
        scanner = NucleiScanner(options={"template_dirs": ["ssl", "dns"]})
        ctx = ScanContext()
        ctx.add_technologies(["nginx", "wordpress"])
        template_dirs, tags, workflows = scanner._resolve_targeted_selection(
            ctx, has_explicit=True
        )
        assert template_dirs == ["ssl", "dns"]
        assert tags == []
        assert workflows == []

    def test_explicit_tags_returned_as_is(self, target: Target) -> None:
        scanner = NucleiScanner(options={"tags": ["cve", "rce"]})
        ctx = ScanContext()
        template_dirs, tags, workflows = scanner._resolve_targeted_selection(
            ctx, has_explicit=True
        )
        assert tags == ["cve", "rce"]

    def test_default_template_dirs_when_no_tech(self, target: Target) -> None:
        scanner = NucleiScanner()
        ctx = ScanContext()
        template_dirs, tags, workflows = scanner._resolve_targeted_selection(
            ctx, has_explicit=False
        )
        assert template_dirs == list(DEFAULT_TEMPLATE_DIRS)
        assert tags == []
        assert workflows == []

    def test_wordpress_tech_adds_tags(self, target: Target) -> None:
        scanner = NucleiScanner()
        ctx = ScanContext()
        ctx.add_technologies(["wordpress"])
        template_dirs, tags, workflows = scanner._resolve_targeted_selection(
            ctx, has_explicit=False
        )
        assert "wordpress" in tags
        assert "wp-plugin" in tags or "wp-theme" in tags

    def test_wordpress_tech_adds_workflow(self, target: Target) -> None:
        scanner = NucleiScanner()
        ctx = ScanContext()
        ctx.add_technologies(["wordpress"])
        template_dirs, tags, workflows = scanner._resolve_targeted_selection(
            ctx, has_explicit=False
        )
        assert "workflows/wordpress-workflow.yaml" in workflows

    def test_multiple_techs_combine_tags(self, target: Target) -> None:
        scanner = NucleiScanner()
        ctx = ScanContext()
        ctx.add_technologies(["wordpress", "nginx", "php"])
        template_dirs, tags, workflows = scanner._resolve_targeted_selection(
            ctx, has_explicit=False
        )
        assert "wordpress" in tags
        assert "nginx" in tags
        assert "php" in tags

    def test_tech_tag_deduplication(self, target: Target) -> None:
        scanner = NucleiScanner()
        ctx = ScanContext()
        ctx.add_technologies(["apache-tomcat", "tomcat"])
        template_dirs, tags, workflows = scanner._resolve_targeted_selection(
            ctx, has_explicit=False
        )
        tomcat_tags = [t for t in tags if "tomcat" in t]
        assert len(tomcat_tags) == len(set(tomcat_tags))

    def test_unknown_tech_no_tags_added(self, target: Target) -> None:
        scanner = NucleiScanner()
        ctx = ScanContext()
        ctx.add_technologies(["unknown-tech-xyz"])
        template_dirs, tags, workflows = scanner._resolve_targeted_selection(
            ctx, has_explicit=False
        )
        assert "unknown-tech-xyz" not in tags

    def test_case_insensitive_tech_matching(self, target: Target) -> None:
        scanner = NucleiScanner()
        ctx = ScanContext()
        ctx.add_technologies(["WordPress", "NGINX"])
        template_dirs, tags, workflows = scanner._resolve_targeted_selection(
            ctx, has_explicit=False
        )
        assert any("wordpress" in t.lower() for t in tags)
        assert any("nginx" in t.lower() for t in tags)


class TestSkipTechDetection:
    def test_skip_tech_detection_true(self, target: Target) -> None:
        scanner = NucleiScanner(options={"skip_tech_detection": True})
        assert scanner.options["skip_tech_detection"] is True

    def test_skip_tech_detection_false_by_default(self, target: Target) -> None:
        scanner = NucleiScanner()
        assert scanner.options["skip_tech_detection"] is False
