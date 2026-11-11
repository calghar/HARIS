import logging
from pathlib import Path

import pytest

import haris
from haris.config.loader import load_config
from haris.models.target import Scope, Target
from haris.scanners.wapiti_scanner import LOOPBACK_ENDPOINT, WapitiScanner

HTTP_BASE = "http://127.0.0.1:14280"
SESSION_DIR = "/tmp/wapiti-session"
DEFAULT_CONFIG = Path(haris.__file__).parent / "resources/config/default_config.yaml"


def exclude_values(cmd: list[str]) -> list[str]:
    return [cmd[i + 1] for i, arg in enumerate(cmd) if arg == "--exclude"]


def build(base_url: str, excluded: list[str]) -> list[str]:
    target = Target(base_url=base_url, scope=Scope(excluded_paths=excluded))
    return WapitiScanner()._build_command(target, "/tmp/out.json", SESSION_DIR)


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


EXTERNAL = "http://callback:9090/"
INTERNAL = "http://127.0.0.1:19090/"
PUBLIC_HOST = "wapiti3.ovh"


def endpoint_cmd(options: dict[str, str]) -> list[str]:
    return WapitiScanner(options)._build_command(
        Target(base_url=HTTP_BASE), "/tmp/o", SESSION_DIR
    )


def module_names(cmd: list[str]) -> list[str]:
    return cmd[cmd.index("--module") + 1].split(",")


def flag_value(cmd: list[str], flag: str) -> str:
    return cmd[cmd.index(flag) + 1]


class TestWapitiEndpointArgv:
    def test_both_endpoints_are_passed_and_callback_modules_run(self) -> None:
        cmd = endpoint_cmd(
            {"external_endpoint": EXTERNAL, "internal_endpoint": INTERNAL}
        )
        assert flag_value(cmd, "--external-endpoint") == EXTERNAL
        assert flag_value(cmd, "--internal-endpoint") == INTERNAL
        spec = module_names(cmd)
        assert "-log4shell" in spec
        assert "-ssrf" not in spec
        assert "-xxe" not in spec

    @pytest.mark.parametrize(
        "options", [{}, {"external_endpoint": "", "internal_endpoint": ""}]
    )
    def test_unset_endpoints_use_the_target_and_skip_callback_modules(
        self, options: dict[str, str]
    ) -> None:
        cmd = endpoint_cmd(options)
        assert flag_value(cmd, "--external-endpoint") == LOOPBACK_ENDPOINT
        assert flag_value(cmd, "--internal-endpoint") == HTTP_BASE
        spec = module_names(cmd)
        assert "-ssrf" in spec
        assert "-xxe" in spec
        assert "-log4shell" in spec
        assert all(PUBLIC_HOST not in arg for arg in cmd)

    @pytest.mark.parametrize(
        ("options", "external", "internal"),
        [
            ({"external_endpoint": EXTERNAL}, EXTERNAL, HTTP_BASE),
            ({"internal_endpoint": INTERNAL}, LOOPBACK_ENDPOINT, INTERNAL),
            (
                {"external_endpoint": EXTERNAL, "internal_endpoint": ""},
                EXTERNAL,
                HTTP_BASE,
            ),
            (
                {"external_endpoint": "", "internal_endpoint": INTERNAL},
                LOOPBACK_ENDPOINT,
                INTERNAL,
            ),
        ],
    )
    def test_one_endpoint_uses_the_placeholder_and_skips_callbacks(
        self, options: dict[str, str], external: str, internal: str
    ) -> None:
        cmd = endpoint_cmd(options)
        assert flag_value(cmd, "--external-endpoint") == external
        assert flag_value(cmd, "--internal-endpoint") == internal
        spec = module_names(cmd)
        assert "-ssrf" in spec
        assert "-xxe" in spec

    @pytest.mark.parametrize(
        "options",
        [
            {},
            {"external_endpoint": EXTERNAL},
            {"internal_endpoint": INTERNAL},
            {"external_endpoint": EXTERNAL, "internal_endpoint": INTERNAL},
            {"external_endpoint": "", "internal_endpoint": ""},
        ],
    )
    def test_argv_never_names_the_public_host(self, options: dict[str, str]) -> None:
        cmd = endpoint_cmd(options)
        assert all(PUBLIC_HOST not in arg for arg in cmd)

    @pytest.mark.parametrize(
        "value", ["callback:9090", "ftp://callback/", "http://", "--evil"]
    )
    def test_non_http_url_is_rejected(self, value: str) -> None:
        with pytest.raises(ValueError, match="external_endpoint"):
            endpoint_cmd({"external_endpoint": value})


class TestWapitiSessionArgv:
    def test_information_disclosure_is_excluded(self) -> None:
        modules = build(HTTP_BASE, [])
        spec = modules[modules.index("--module") + 1].split(",")
        assert "-information_disclosure" in spec

    def test_store_session_uses_the_given_directory(self) -> None:
        cmd = build(HTTP_BASE, [])
        assert cmd[cmd.index("--store-session") + 1] == SESSION_DIR
