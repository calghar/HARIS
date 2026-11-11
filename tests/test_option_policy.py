import pytest

from haris.db.template_defaults import default_templates
from haris.models import Target
from haris.scanners.option_policy import (
    ScannerOptionsError,
    prepare_web_scanner_options,
)
from haris.scanners.wapiti_scanner import WapitiScanner

LOOPBACK = "http://127.0.0.1:9/"
FORM_OPTIONS = {
    "nuclei": {
        "template_dirs": ["http/vulnerabilities"],
        "tags": ["cve"],
        "severity": ["high"],
        "exclude_tags": ["dos"],
        "rate_limit": 150,
        "max_host_errors": 500,
        "timeout": 600,
    },
    "nikto": {"tuning": ["1"], "timeout": 300},
    "nmap": {"ports": "80,443", "script_categories": ["safe"], "timeout": 300},
    "wapiti": {
        "modules": "all",
        "scope": "folder",
        "max_scan_time": 600,
        "max_links": 500,
        "timeout": 300,
    },
    "sslyze": {"timeout": 120},
    "header_checks": {"follow_redirects": False},
    "tls_checks": {"cert_expiry_warn_days": 30},
    "misc_checks": {
        "check_cors": True,
        "check_redirect": True,
        "check_sensitive_paths": True,
    },
    "info_disclosure": {
        "check_error_pages": True,
        "check_debug_endpoints": True,
        "check_html_comments": True,
        "check_version_endpoints": True,
    },
}


def test_h3_builtin_template_options_pass() -> None:
    for template in default_templates():
        assert (
            prepare_web_scanner_options(template.scanner_options, allow_private=False)
            == template.scanner_options
        )
    assert (
        prepare_web_scanner_options(FORM_OPTIONS, allow_private=False) == FORM_OPTIONS
    )


def test_h3_url_option_follows_private_target_policy(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("HARIS_ALLOW_PRIVATE_TARGETS", raising=False)
    options = {"wapiti": {"external_endpoint": "http://10.0.0.5/"}}
    with pytest.raises(ScannerOptionsError, match="not allowed") as caught:
        prepare_web_scanner_options(options)
    assert "10.0.0.5" not in str(caught.value)
    monkeypatch.setenv("HARIS_ALLOW_PRIVATE_TARGETS", "true")
    assert prepare_web_scanner_options(options) == options


def test_h3_hostname_url_is_vetted_with_the_resolver() -> None:
    def resolver(host: str, _port: int) -> list[str]:
        assert host == "callback.example"
        return ["10.1.1.1"]

    with pytest.raises(ScannerOptionsError, match="not allowed") as caught:
        prepare_web_scanner_options(
            {"wapiti": {"internal_endpoint": "http://callback.example/hook"}},
            allow_private=False,
            resolver=resolver,
        )
    assert "callback.example" not in str(caught.value)
    assert "10.1.1.1" not in str(caught.value)


def test_h3_empty_endpoint_is_kept_and_non_http_is_rejected() -> None:
    kept = prepare_web_scanner_options(
        {"wapiti": {"external_endpoint": ""}}, allow_private=False
    )
    assert kept["wapiti"]["external_endpoint"] == ""
    with pytest.raises(ScannerOptionsError, match="http"):
        prepare_web_scanner_options(
            {"wapiti": {"external_endpoint": "ftp://example.com/x"}},
            allow_private=False,
        )


def test_h3_web_rejects_redirect_flags_and_strips_gate_flags() -> None:
    with pytest.raises(ScannerOptionsError, match="-fr"):
        prepare_web_scanner_options(
            {"nuclei": {"extra_args": ["-fr"]}}, allow_private=False
        )
    with pytest.raises(ScannerOptionsError, match="-followredirects"):
        prepare_web_scanner_options(
            {"nikto": {"extra_args": ["-followredirects"]}}, allow_private=False
        )
    with pytest.raises(ScannerOptionsError, match="unknown option"):
        prepare_web_scanner_options(
            {"nuclei": {"not_a_real_option": 1}}, allow_private=False
        )
    cleaned = prepare_web_scanner_options(
        {
            "ai": {"active": True},
            "ai_security": {"active": True, "authorised": True, "max_prompts": 3},
        },
        allow_private=False,
    )
    assert cleaned == {"ai_security": {"max_prompts": 3}}


def test_h3_cli_loopback_wapiti_endpoint_passes() -> None:
    scanner = WapitiScanner(
        options={"external_endpoint": LOOPBACK, "internal_endpoint": LOOPBACK}
    )
    command = scanner._build_command(
        Target(base_url="https://example.com"), "/tmp/out.json", "/tmp/session"
    )
    assert command.count(LOOPBACK) == 2
