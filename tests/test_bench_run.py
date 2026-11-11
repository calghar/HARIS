import importlib.util
import subprocess
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest
import yaml

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


def test_verify_option_is_appended_after_target_args() -> None:
    target = runner.TARGETS["vuln_ai_app"]
    assert runner.parse_args([]).verify is None
    assert runner.run_args(target, None) == target.haris_args
    assert runner.run_args(target, "replay") == (
        *target.haris_args,
        "--verify",
        "replay",
    )


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


def capture_scan_config(
    name: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> tuple[list[str], dict[str, Any] | None]:
    seen: list[tuple[list[str], dict[str, Any] | None]] = []

    def fake_run(cmd: list[str], **_: Any) -> subprocess.CompletedProcess[str]:
        config = None
        if "--config" in cmd:
            config = yaml.safe_load(Path(cmd[cmd.index("--config") + 1]).read_text())
        out = Path(cmd[cmd.index("--output") + 1])
        (out / "report.json").write_text("{}")
        seen.append((cmd, config))
        return subprocess.CompletedProcess(cmd, 0, "", "")

    monkeypatch.setattr(runner, "WAPITI_ENDPOINTS", {})
    monkeypatch.setattr(runner, "TARGET_EXCLUDED_PATHS", [])
    monkeypatch.setattr(runner, "compose", lambda *a: None)
    monkeypatch.setattr(runner, "resolve_base_url", lambda t: "http://127.0.0.1:1")
    monkeypatch.setattr(runner, "wait_healthy", lambda *a: None)
    monkeypatch.setattr(runner, "score", lambda *a: None)
    monkeypatch.setattr(runner.subprocess, "run", fake_run)
    monkeypatch.setitem(runner.LOGIN, "dvwa", lambda url: None)
    monkeypatch.setitem(runner.PREPARE, "dvwa", lambda url: None)
    runner.scan_target(name, runner.parse_args(["--runs", "1"]), tmp_path)
    return seen[0]


def default_excluded_paths() -> list[str]:
    raw = yaml.safe_load(runner.default_config_path().read_text())
    return list(raw["target"]["scope"]["excluded_paths"])


def test_only_dvwa_carries_excluded_paths() -> None:
    carriers = {
        n: t.excluded_paths for n, t in runner.TARGETS.items() if t.excluded_paths
    }
    assert carriers == {"dvwa": ("/logout.php", "/setup.php")}


def test_dvwa_config_extends_the_default_excluded_paths_without_a_session(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    cmd, config = capture_scan_config("dvwa", tmp_path, monkeypatch)
    assert config is not None
    assert config["target"]["scope"]["excluded_paths"] == [
        *default_excluded_paths(),
        "/logout.php",
        "/setup.php",
    ]
    assert "/logout.php" not in " ".join(cmd)


def run_command_config(
    monkeypatch: pytest.MonkeyPatch, excluded: list[str], cookie: str | None = None
) -> tuple[list[str], dict[str, Any] | None]:
    seen: list[tuple[list[str], dict[str, Any] | None]] = []

    def fake_run(cmd: list[str], **_: Any) -> subprocess.CompletedProcess[str]:
        config = None
        if "--config" in cmd:
            config = yaml.safe_load(Path(cmd[cmd.index("--config") + 1]).read_text())
        seen.append((cmd, config))
        return subprocess.CompletedProcess(cmd, 0, "", "")

    monkeypatch.setattr(runner, "WAPITI_ENDPOINTS", {})
    monkeypatch.setattr(runner, "TARGET_EXCLUDED_PATHS", excluded)
    monkeypatch.setattr(runner.subprocess, "run", fake_run)
    runner.run_command(["haris"], cookie)
    return seen[0]


def test_config_is_written_for_excludes_alone(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    cmd, config = run_command_config(monkeypatch, ["/setup.php"])
    assert config is not None
    assert config["target"]["scope"]["excluded_paths"][-1] == "/setup.php"


def test_no_config_without_excludes_cookie_or_endpoints(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    cmd, config = run_command_config(monkeypatch, [])
    assert cmd == ["haris"]
    assert config is None


def test_target_path_equal_to_a_default_entry_is_not_repeated(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _, config = run_command_config(monkeypatch, ["/logout", "/logout.php"], "s=1")
    assert config is not None
    assert config["target"]["scope"]["excluded_paths"] == [
        *default_excluded_paths(),
        "/logout.php",
    ]
