import logging
from pathlib import Path

import pytest

import haris
from haris.config.loader import load_config
from haris.models.target import Scope, Target
from haris.scanners.wapiti_scanner import WapitiScanner

HTTP_BASE = "http://127.0.0.1:14280"
DEFAULT_CONFIG = Path(haris.__file__).parent / "resources/config/default_config.yaml"


def exclude_values(cmd: list[str]) -> list[str]:
    return [cmd[i + 1] for i, arg in enumerate(cmd) if arg == "--exclude"]


def build(base_url: str, excluded: list[str]) -> list[str]:
    target = Target(base_url=base_url, scope=Scope(excluded_paths=excluded))
    return WapitiScanner()._build_command(target, "/tmp/out.json")


class TestWapitiExcludeArgv:
    def test_default_config_paths_become_absolute_urls(self) -> None:
        excluded = load_config(DEFAULT_CONFIG).target.scope.excluded_paths
        assert excluded, "default config must list excluded paths"
        assert exclude_values(build(HTTP_BASE, excluded)) == [
            f"{HTTP_BASE}/logout",
            f"{HTTP_BASE}/api/admin/*",
        ]

    def test_regex_wildcard_suffix_becomes_star(self) -> None:
        assert exclude_values(build(HTTP_BASE, ["/a/b.*"])) == [f"{HTTP_BASE}/a/b*"]

    def test_https_keeps_scheme_and_port(self) -> None:
        values = exclude_values(build("https://app.example.com:8443", ["/logout"]))
        assert values == ["https://app.example.com:8443/logout"]

    @pytest.mark.parametrize("regex", ["^/admin", "/(a|b)", "/x[0-9]+", "/a$", "/a.*b"])
    def test_regex_syntax_is_skipped_with_warning(
        self, regex: str, caplog: pytest.LogCaptureFixture
    ) -> None:
        with caplog.at_level(logging.WARNING):
            cmd = build(HTTP_BASE, [regex, "/logout"])
        assert exclude_values(cmd) == [f"{HTTP_BASE}/logout"]
        assert regex not in cmd
        warnings = [r for r in caplog.records if r.levelno == logging.WARNING]
        assert len(warnings) == 1
        assert regex in warnings[0].getMessage()
        assert "regex" in warnings[0].getMessage()

    def test_no_exclusions_adds_no_flag(self) -> None:
        assert "--exclude" not in build(HTTP_BASE, [])


def endpoint_cmd(options: dict[str, str]) -> list[str]:
    return WapitiScanner(options)._build_command(Target(base_url=HTTP_BASE), "/tmp/o")


class TestWapitiEndpointArgv:
    def test_endpoint_options_become_flags_and_drop_the_dns_module(self) -> None:
        cmd = endpoint_cmd(
            {
                "external_endpoint": "http://callback:9090/",
                "internal_endpoint": "http://127.0.0.1:19090/",
            }
        )
        assert cmd[cmd.index("--external-endpoint") + 1] == "http://callback:9090/"
        assert cmd[cmd.index("--internal-endpoint") + 1] == "http://127.0.0.1:19090/"
        assert "-log4shell" in cmd[cmd.index("--module") + 1].split(",")

    def test_unset_endpoints_keep_wapiti_defaults(self) -> None:
        cmd = endpoint_cmd({})
        assert not {"--endpoint", "--external-endpoint", "--internal-endpoint"} & set(
            cmd
        )
        assert "-log4shell" not in cmd[cmd.index("--module") + 1].split(",")

    @pytest.mark.parametrize(
        "value", ["callback:9090", "ftp://callback/", "http://", "--evil"]
    )
    def test_non_http_url_is_rejected(self, value: str) -> None:
        with pytest.raises(ValueError, match="external_endpoint"):
            endpoint_cmd({"external_endpoint": value})
