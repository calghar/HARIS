import importlib.util
import subprocess
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

RUN_PY = Path(__file__).resolve().parent.parent / "bench" / "run.py"


def load_runner() -> ModuleType:
    spec = importlib.util.spec_from_file_location("bench_run", RUN_PY)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


runner = load_runner()


def test_target_profile_is_used_when_no_override_is_given() -> None:
    assert runner.resolve_profile(runner.TARGETS["vuln_ai_app"], None) == "ai-security"
    assert runner.resolve_profile(runner.TARGETS["spa_catchall"], None) == "quick"


def test_profile_option_overrides_every_target() -> None:
    profiles = {
        runner.resolve_profile(target, "full") for target in runner.TARGETS.values()
    }
    assert profiles == {"full"}


def test_profile_option_is_optional() -> None:
    assert runner.parse_args([]).profile is None
    assert runner.parse_args(["--profile", "full"]).profile == "full"


def test_vuln_ai_app_runs_with_active_probes_and_authorization() -> None:
    assert runner.TARGETS["vuln_ai_app"].haris_args == (
        "--ai-active",
        "--i-have-authorization",
    )
    assert runner.TARGETS["spa_catchall"].haris_args == ()


def test_haris_command_carries_profile_and_extra_args(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    seen: list[list[str]] = []

    def fake_run(cmd: list[str], **_: Any) -> subprocess.CompletedProcess[str]:
        seen.append(cmd)
        (tmp_path / "out" / "report.json").write_text("{}")
        return subprocess.CompletedProcess(cmd, 2, "", "")

    (tmp_path / "out").mkdir()
    monkeypatch.setattr(runner.subprocess, "run", fake_run)
    runner.run_haris(
        ["haris"],
        "http://127.0.0.1:1",
        "ai-security",
        tmp_path / "out",
        tmp_path / "run1.json",
        ("--ai-active", "--i-have-authorization"),
    )
    cmd = seen[0]
    assert cmd[cmd.index("--profile") + 1] == "ai-security"
    assert cmd[-2:] == ["--ai-active", "--i-have-authorization"]
    assert (tmp_path / "run1.json").exists()


def test_target_and_its_database_are_removed_even_when_the_scan_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls: list[tuple[str, ...]] = []

    def fake_compose(*args: str) -> None:
        calls.append(args)
        if args[0] == "up":
            raise subprocess.CalledProcessError(1, "docker")

    monkeypatch.setattr(runner, "compose", fake_compose)
    with pytest.raises(subprocess.CalledProcessError):
        runner.bench_target("dvwa", runner.parse_args([]), tmp_path)
    assert calls[-1] == ("rm", "--stop", "--force", "--volumes", "dvwa", "dvwa_db")


def test_each_invocation_writes_to_a_new_results_directory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    stamps = iter(["2026-11-10-100000", "2026-11-10-100001"])

    class FixedClock:
        @staticmethod
        def now(tz: object) -> Any:
            class Stamp:
                @staticmethod
                def strftime(fmt: str) -> str:
                    assert fmt == runner.RESULTS_STAMP
                    return next(stamps)

            return Stamp()

    monkeypatch.setattr(runner, "datetime", FixedClock)
    monkeypatch.setattr(
        runner, "compose", lambda *a: subprocess.CompletedProcess(a, 0, "", "")
    )
    argv = ["--targets", "spa_catchall", "--results-dir", str(tmp_path)]
    monkeypatch.setattr(runner, "bench_target", lambda *a: None)
    assert runner.main(argv) == 0
    assert runner.main(argv) == 0
    assert sorted(p.name for p in tmp_path.iterdir()) == [
        "2026-11-10-100000",
        "2026-11-10-100001",
    ]
