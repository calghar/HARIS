"""Shared scanner runtime: process-group timeout, argv policy, redaction."""

import os
import sys
import textwrap
import time
from typing import Any
from unittest.mock import patch

import pytest

from haris.models.target import AuthConfig, Scope, Target
from haris.scanners.argv_policy import ExtraArgsError, validate_extra_args
from haris.scanners.nikto_scanner import NiktoScanner
from haris.scanners.nmap_scanner import NmapScanner
from haris.scanners.nuclei_scanner import NucleiScanner
from haris.scanners.process import ToolTimeoutError, run_process
from haris.scanners.redaction import REDACTED, redact_argv, redact_obj, redact_text
from haris.scanners.sslyze_scanner import SSLyzeScanner
from haris.scanners.wapiti_scanner import WapitiScanner
from tests.conftest import bound_context

SCANNER_CLASSES: dict[str, Any] = {
    "nikto": NiktoScanner,
    "nmap": NmapScanner,
    "nuclei": NucleiScanner,
    "sslyze": SSLyzeScanner,
    "wapiti": WapitiScanner,
}
DISALLOWED = [
    ["-o", "/tmp/x"],
    ["-oX", "/tmp/x"],
    ["--output=/tmp/x"],
    ["--script", "default"],
    ["--script=default"],
    ["--"],
    ["example.org"],
]
FORK_CHILD = textwrap.dedent(
    """
    import os, time
    grandchild = os.fork()
    if grandchild == 0:
        time.sleep(60)
        os._exit(0)
    print(os.getpid(), grandchild, flush=True)
    time.sleep(60)
    """
)


@pytest.fixture
def target() -> Target:
    return Target(base_url="https://example.com", scope=Scope())


def _build(instance: Any, target: Target) -> list[str]:
    cmd: list[str]
    if isinstance(instance, NucleiScanner):
        cmd = instance._build_command(target)
    elif isinstance(instance, WapitiScanner):
        cmd = instance._build_command(target, "/tmp/out", "/tmp/wapiti-session")
    else:
        cmd = instance._build_command(target, "/tmp/out")
    return cmd


def _gone(pid: int, wait: float = 3.0) -> bool:
    deadline = time.monotonic() + wait
    while time.monotonic() < deadline:
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            return True
        time.sleep(0.05)
    return False


class TestProcessGroupTimeout:
    def test_timeout_kills_grandchild_and_keeps_partial_stdout(self) -> None:
        with pytest.raises(ToolTimeoutError) as caught:
            run_process([sys.executable, "-c", FORK_CHILD], timeout=1)
        child, grandchild = (int(p) for p in caught.value.stdout.split())
        assert _gone(child)
        assert _gone(grandchild)

    def test_normal_run_returns_output(self) -> None:
        code, out, err = run_process([sys.executable, "-c", "print('ok')"], timeout=10)
        assert (code, out.strip(), err) == (0, "ok", "")

    def test_scanner_timeout_names_scanner(self) -> None:
        scanner = NiktoScanner()
        with pytest.raises(ToolTimeoutError, match="nikto timed out after 1s"):
            scanner._run_command([sys.executable, "-c", FORK_CHILD], timeout=1)


class TestExtraArgsAllowList:
    @pytest.mark.parametrize("scanner", sorted(SCANNER_CLASSES))
    @pytest.mark.parametrize("args", DISALLOWED, ids=" ".join)
    def test_disallowed_flag_rejected(self, scanner: str, args: list[str]) -> None:
        with pytest.raises(ExtraArgsError, match="not allowed"):
            validate_extra_args(scanner, args)

    @pytest.mark.parametrize("scanner", sorted(SCANNER_CLASSES))
    def test_build_command_rejects_disallowed(
        self, scanner: str, target: Target
    ) -> None:
        instance = SCANNER_CLASSES[scanner]({"extra_args": ["-o", "/tmp/x"]})
        with pytest.raises(ExtraArgsError):
            _build(instance, target)

    @pytest.mark.parametrize("scanner", sorted(SCANNER_CLASSES))
    def test_scan_reports_clear_error_and_runs_nothing(
        self, scanner: str, target: Target
    ) -> None:
        instance = SCANNER_CLASSES[scanner]({"extra_args": ["-o", "/tmp/x"]})
        with (
            patch.object(instance, "_check_tool_available", return_value=True),
            patch("haris.scanners.base.run_process") as run,
        ):
            run.return_value = (0, "", "")
            result = instance.scan(target, bound_context())
        assert any("not allowed" in e for e in result.errors)
        assert not any(
            "/tmp/x" in " ".join(call.args[0]) for call in run.call_args_list
        )

    def test_allowed_flags_pass(self) -> None:
        assert validate_extra_args("nmap", ["-T4", "--max-rate", "50"]) == [
            "-T4",
            "--max-rate",
            "50",
        ]

    def test_flag_equals_value_form(self) -> None:
        assert validate_extra_args("nmap", ["--max-rate=50"]) == ["--max-rate=50"]

    def test_unsafe_value_rejected(self) -> None:
        with pytest.raises(ExtraArgsError):
            validate_extra_args("nmap", ["--max-rate", "-oX"])

    def test_missing_value_rejected(self) -> None:
        with pytest.raises(ExtraArgsError, match="needs 1 value"):
            validate_extra_args("nmap", ["--max-rate"])

    def test_non_list_rejected(self) -> None:
        with pytest.raises(ExtraArgsError, match="list of strings"):
            validate_extra_args("nmap", "-T4")


class TestHostArguments:
    def test_nmap_double_dash_before_host(self, target: Target) -> None:
        cmd = NmapScanner()._build_command(target, "/tmp/out.xml")
        assert cmd[-2:] == ["--", "example.com"]

    def test_sslyze_double_dash_before_host(self, target: Target) -> None:
        cmd = SSLyzeScanner()._build_command(target, "/tmp/out.json")
        assert cmd[-2:] == ["--", "example.com:443"]

    def test_extra_args_stay_before_double_dash(self, target: Target) -> None:
        scanner = NmapScanner({"extra_args": ["-Pn"]})
        cmd = scanner._build_command(target, "/tmp/out.xml")
        assert cmd.index("-Pn") < cmd.index("--")

    @pytest.mark.parametrize(
        ("scanner", "flag"),
        [(NiktoScanner, "-host"), (NucleiScanner, "-u"), (WapitiScanner, "--url")],
    )
    def test_host_bound_to_flag(self, scanner: type, flag: str, target: Target) -> None:
        cmd = _build(scanner(), target)
        assert cmd[cmd.index(flag) + 1] == "https://example.com"


class TestRedactionHelpers:
    @pytest.mark.parametrize(
        "text",
        [
            "Authorization: Bearer abc123token",
            "authorization: Bearer abc123token",
            "X-API-Key: abc123token",
            "Cookie: sid=abc123token",
            '{"request": "GET / HTTP/1.1\\r\\nx-api-key: abc123token\\r\\n"}',
            "curl -H 'Authorization: Bearer abc123token' http://h/",
        ],
    )
    def test_header_values_masked(self, text: str) -> None:
        assert "abc123token" not in redact_text(text)

    def test_known_secret_masked_anywhere(self) -> None:
        assert (
            redact_text("url?k=s3cr3t-value", ("s3cr3t-value",)) == f"url?k={REDACTED}"
        )

    def test_dict_keys_masked(self) -> None:
        data = {"Authorization": "Bearer x1y2z3", "nested": [{"x-api-key": "k9k9k9"}]}
        out = redact_obj(data)
        assert out["Authorization"] == REDACTED
        assert out["nested"][0]["x-api-key"] == REDACTED

    def test_plain_text_untouched(self) -> None:
        assert redact_text("Server: Apache/2.2.8") == "Server: Apache/2.2.8"

    @pytest.mark.parametrize("flag", ["-H", "-header"])
    def test_argv_keeps_flags_after_a_cookie_header_with_spaces(
        self, flag: str
    ) -> None:
        argv = ["nuclei", flag, "Cookie: a=b; c=d", "-rl", "3"]

        assert redact_argv(argv) == f"nuclei {flag} Cookie: {REDACTED} -rl 3"

    def test_argv_masks_any_header_value_and_known_secrets(self) -> None:
        argv = [
            "nuclei",
            "-H",
            "X-Other: plain value",
            "-u",
            "http://h/?k=s3cr3t-value",
        ]

        assert redact_argv(argv, ("s3cr3t-value",)) == (
            f"nuclei -H X-Other: {REDACTED} -u http://h/?k={REDACTED}"
        )


class TestArgvLogRedaction:
    @pytest.mark.parametrize(
        ("scanner", "secret"),
        [("nikto", "nikto-secret-1"), ("wapiti", "wapiti-secret-1")],
    )
    def test_auth_header_not_logged(
        self,
        scanner: str,
        secret: str,
        target: Target,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        target.auth = AuthConfig(
            method="header", header_name="X-API-Key", header_value=secret
        )
        instance = SCANNER_CLASSES[scanner]()
        with (
            patch.object(instance, "_check_tool_available", return_value=True),
            patch("haris.scanners.base.run_process", return_value=(0, "", "")),
            caplog.at_level("DEBUG"),
        ):
            instance.scan(target, bound_context())
        assert secret not in caplog.text
        assert REDACTED in caplog.text

    def test_cookie_auth_not_logged(
        self, target: Target, caplog: pytest.LogCaptureFixture
    ) -> None:
        target.auth = AuthConfig(
            method="cookie", cookie_name="sid", cookie_value="cookie-secret-1"
        )
        instance = NiktoScanner()
        with (
            patch.object(instance, "_check_tool_available", return_value=True),
            patch("haris.scanners.base.run_process", return_value=(0, "", "")),
            caplog.at_level("DEBUG"),
        ):
            instance.scan(target, bound_context())
        assert "cookie-secret-1" not in caplog.text


def test_run_command_maps_missing_binary_to_runtime_error() -> None:
    scanner = NiktoScanner()
    with (
        patch("haris.scanners.base.run_process", side_effect=FileNotFoundError),
        pytest.raises(RuntimeError, match="not found"),
    ):
        scanner._run_command(["nikto"], timeout=1)
