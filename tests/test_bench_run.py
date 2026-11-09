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
