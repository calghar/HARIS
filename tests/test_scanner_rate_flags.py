import os
import stat
import subprocess
from pathlib import Path
from typing import Any

import pytest

from haris.core.engine import ScanEngine
from haris.core.scanner import BaseScanner
from haris.data import scanner_config
from haris.models.target import Target
from haris.scanners.nikto_scanner import NiktoScanner
from haris.scanners.nmap_scanner import NmapScanner
from haris.scanners.nuclei_scanner import NucleiScanner
from haris.scanners.option_policy import (
    ScannerOptionsError,
    prepare_web_scanner_options,
)
from tests.conftest import bound_context
from tests.test_engine_pipeline import TARGET
from tests.test_scanner_binding import (
    HTTPS_URL,
    LITERAL_URL,
    after,
    run_scan,
    scanner_for,
)

FLAGS = {"nmap": "--max-rate", "nuclei": "-rl", "nikto": "-Pause"}
RAISING_EXTRA_ARGS = {
    "nmap": ["--max-rate", "1000"],
    "nuclei": ["-rl", "1000"],
    "nikto": ["-Pause", "0"],
}


@pytest.fixture(autouse=True)
def nuclei_without_templates(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(NucleiScanner, "_check_templates_available", lambda _s: True)
    monkeypatch.setattr(NucleiScanner, "_template_root", lambda _s: None)


def tool_argvs(tool: str, rate: float, **options: Any) -> list[list[str]]:
    scanner = scanner_for(tool, **options)
    _, argvs = run_scan(scanner, HTTPS_URL, bound_context(tool_rate_rps=rate))
    assert argvs, f"{tool} never started"
    return argvs


def last_value(argv: list[str], flag: str) -> str:
    return argv[len(argv) - 1 - argv[::-1].index(flag) + 1]


class TestFlagFromBoundContext:
    @pytest.mark.parametrize(
        ("tool", "rate", "value"),
        [
            ("nmap", 10.0, "10"),
            ("nmap", 2.5, "2.5"),
            ("nuclei", 5.0, "5"),
            ("nuclei", 3.33, "3"),
            ("nuclei", 1.0, "1"),
            ("nikto", 5.0, "0.2"),
            ("nikto", 10.0, "0.1"),
            ("nikto", 1.0, "1"),
            ("nikto", 3.0, "0.333333"),
            ("nikto", 0.5, "2"),
        ],
    )
    def test_flag_carries_the_rate(self, tool: str, rate: float, value: str) -> None:
        for argv in tool_argvs(tool, rate):
            assert after(argv, FLAGS[tool]) == value

    def test_every_nuclei_run_gets_the_flag(self) -> None:
        argvs = tool_argvs("nuclei", 5.0)

        assert len(argvs) == 2, "expected the tag group and the baseline group"
        assert [last_value(argv, "-rl") for argv in argvs] == ["5", "5"]

    def test_nuclei_floors_below_one_to_one(self) -> None:
        scanner = NucleiScanner()
        scanner._begin(Target(base_url=HTTPS_URL), bound_context(tool_rate_rps=0.5))

        argv = scanner._build_command(Target(base_url=HTTPS_URL))

        assert after(argv, "-rl") == "1"

    def test_nuclei_rate_limit_option_can_lower_the_split(self) -> None:
        for argv in tool_argvs("nuclei", 5.0, rate_limit=2):
            assert last_value(argv, "-rl") == "2"


class TestOneRateFlag:
    @pytest.mark.parametrize(
        ("rate", "flag", "value"),
        [(5.0, "-rl", "5"), (0.0, "-rate-limit", "100")],
    )
    def test_argv_holds_one_rate_flag(self, rate: float, flag: str, value: str) -> None:
        scanner = NucleiScanner()
        scanner._begin(Target(base_url=HTTPS_URL), bound_context(tool_rate_rps=rate))

        argv = scanner._build_command(Target(base_url=HTTPS_URL))

        assert [t for t in argv if t in {"-rl", "-rate-limit"}] == [flag]
        assert after(argv, flag) == value


class TestNoRateNoFlag:
    @pytest.mark.parametrize("tool", FLAGS)
    def test_unset_rate_adds_nothing(self, tool: str) -> None:
        for argv in tool_argvs(tool, 0.0):
            assert FLAGS[tool] not in argv

    def test_no_context_adds_nothing(self) -> None:
        _, argvs = run_scan(NmapScanner(), LITERAL_URL, None)

        assert argvs
        assert "--max-rate" not in argvs[0]

    def test_command_built_without_begin_adds_nothing(self) -> None:
        argv = NucleiScanner()._build_command(Target(base_url=HTTPS_URL))

        assert "-rl" not in argv


class TestFlagFollowsExtraArgs:
    @pytest.mark.parametrize(
        ("tool", "split"), [("nmap", "5"), ("nuclei", "5"), ("nikto", "0.2")]
    )
    def test_user_flag_cannot_override_the_split(self, tool: str, split: str) -> None:
        flag = FLAGS[tool]
        for argv in tool_argvs(tool, 5.0, extra_args=RAISING_EXTRA_ARGS[tool]):
            values = [argv[i + 1] for i, token in enumerate(argv) if token == flag]
            assert values == [RAISING_EXTRA_ARGS[tool][1], split]


class TestPhase2TimeoutMustBePositive:
    @pytest.mark.parametrize("value", [0, 0.0, -1, float("nan")])
    def test_yaml_getter_rejects(
        self, value: float, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(
            scanner_config,
            "_load_scanner_config",
            lambda _n: {"phase2_timeout_s": value},
        )
        with pytest.raises(ValueError, match="phase2_timeout_s must be greater than 0"):
            scanner_config.get_nuclei_phase2_timeout()

    @pytest.mark.parametrize("value", [0, 0.0, -5])
    def test_web_option_policy_rejects(self, value: float) -> None:
        with pytest.raises(ScannerOptionsError, match="nuclei.phase2_timeout_s"):
            prepare_web_scanner_options({"nuclei": {"phase2_timeout_s": value}})

    @pytest.mark.parametrize("value", [0, -1])
    def test_scanner_option_rejects(self, value: float) -> None:
        with pytest.raises(ValueError, match="greater than 0"):
            NucleiScanner({"phase2_timeout_s": value})._phase2_limit()

    def test_small_positive_value_is_kept(self) -> None:
        options = {"nuclei": {"phase2_timeout_s": 0.5}}

        assert prepare_web_scanner_options(options) == options
        assert NucleiScanner({"phase2_timeout_s": 0.5})._phase2_limit() == 0.5


class StubBinaries:
    def __init__(self, bin_dir: Path) -> None:
        self.bin_dir = bin_dir

    def argvs(self, tool: str) -> list[list[str]]:
        log = self.bin_dir / f"{tool}.log"
        return [line.split() for line in log.read_text().splitlines()]


@pytest.fixture
def stub_binaries(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> StubBinaries:
    """nmap, nuclei and nikto stubs on PATH that log their argv and print nothing."""
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    for tool in FLAGS:
        script = bin_dir / tool
        script.write_text(f'#!/bin/sh\necho "$@" >> {bin_dir / tool}.log\n')
        script.chmod(script.stat().st_mode | stat.S_IXUSR)
        # A new file's first exec can stall for seconds on macOS.
        subprocess.run([script], check=True)
        (bin_dir / f"{tool}.log").unlink()
    monkeypatch.setenv("PATH", f"{bin_dir}{os.pathsep}{os.environ['PATH']}")
    return StubBinaries(bin_dir)


def test_rate_split_scenario_reaches_the_argv_of_the_real_scanners(
    stub_binaries: StubBinaries,
) -> None:
    """Scenario: Rate split (10 rps, parallel 2, nmap alone in the first stage)."""
    scanners: list[BaseScanner] = [
        NmapScanner(),
        NucleiScanner(),
        NiktoScanner(),
    ]
    ScanEngine(scanners=scanners, parallel=2).run(TARGET)

    nmap = stub_binaries.argvs("nmap")
    nuclei = [a for a in stub_binaries.argvs("nuclei") if "-jsonl" in a]
    nikto = stub_binaries.argvs("nikto")
    assert [after(a, "--max-rate") for a in nmap] == ["10"]
    assert nuclei, "nuclei never ran a scan"
    assert {last_value(a, "-rl") for a in nuclei} == {"5"}
    assert [after(a, "-Pause") for a in nikto] == ["0.2"]
