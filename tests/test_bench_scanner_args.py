import importlib.util
import subprocess
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest
import yaml

from haris.models.target import Scope, Target
from haris.scanners.argv_policy import validate_extra_args
from haris.scanners.nikto_scanner import NiktoScanner

BENCH = Path(__file__).resolve().parent.parent / "bench"
NIKTO_ARGS = ["-maxtime", "40s"]


def load(path: Path, name: str) -> ModuleType:
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


callback = load(BENCH / "callback.py", "bench_callback_scanner_args")
runner = load(BENCH / "run.py", "bench_run_scanner_args")


def nikto_options(config: dict[str, Any]) -> dict[str, Any]:
    entry = next(s for s in config["scanners"] if s["name"] == "nikto")
    options: dict[str, Any] = entry["options"]
    return options


def scan_config(
    name: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> dict[str, Any]:
    seen: list[dict[str, Any]] = []

    def fake_run(cmd: list[str], **_: Any) -> subprocess.CompletedProcess[str]:
        seen.append(yaml.safe_load(Path(cmd[cmd.index("--config") + 1]).read_text()))
        out = Path(cmd[cmd.index("--output") + 1])
        (out / "report.json").write_text("{}")
        return subprocess.CompletedProcess(cmd, 0, "", "")

    monkeypatch.setattr(runner.execute, "WAPITI_ENDPOINTS", {})
    monkeypatch.setattr(runner.execute, "TARGET_EXCLUDED_PATHS", [])
    monkeypatch.setattr(runner.execute, "TARGET_SCANNER_ARGS", {})
    monkeypatch.setattr(runner, "compose", lambda *a: None)
    monkeypatch.setattr(runner, "resolve_base_url", lambda t: "http://127.0.0.1:1")
    monkeypatch.setattr(runner, "wait_healthy", lambda *a: None)
    monkeypatch.setattr(runner, "score", lambda *a: None)
    monkeypatch.setattr(runner.subprocess, "run", fake_run)
    monkeypatch.setitem(runner.LOGIN, "dvwa", lambda url: None)
    monkeypatch.setitem(runner.PREPARE, "dvwa", lambda url: None)
    runner.scan_target(name, runner.parse_args(["--runs", "1"]), tmp_path)
    return seen[0]


def test_only_juice_shop_carries_scanner_extra_args() -> None:
    carriers = {
        n: t.scanner_extra_args
        for n, t in runner.TARGETS.items()
        if t.scanner_extra_args
    }
    assert carriers == {"juice_shop": {"nikto": tuple(NIKTO_ARGS)}}
    assert runner.prepare.JUICE_NIKTO_MAX_TIME == "40s"


def test_juice_shop_config_bounds_nikto_and_keeps_its_timeout(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    config = scan_config("juice_shop", tmp_path, monkeypatch)
    assert nikto_options(config) == {"timeout": 300, "extra_args": NIKTO_ARGS}


def test_other_targets_leave_nikto_extra_args_unset(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    config = scan_config("dvwa", tmp_path, monkeypatch)
    assert "extra_args" not in nikto_options(config)


def test_nikto_builds_an_accepted_argv_with_the_bound() -> None:
    config = {"scanners": [{"name": "nikto", "options": {"timeout": 300}}]}
    callback.apply_scanner_extra_args(config, {"nikto": ("-maxtime", "40s")})
    options = nikto_options(config)
    assert validate_extra_args("nikto", options["extra_args"]) == NIKTO_ARGS
    cmd = NiktoScanner(options=options)._build_command(
        Target(base_url="http://127.0.0.1:3000", scope=Scope()), "out"
    )
    assert cmd[cmd.index("-maxtime") + 1] == "40s"


def test_existing_extra_args_are_extended_without_duplicates() -> None:
    config = {
        "scanners": [
            {"name": "nikto", "options": {"extra_args": ["-timeout", "40s"]}},
            {"name": "nuclei"},
        ]
    }
    wanted = {"nikto": ("-maxtime", "40s")}
    callback.apply_scanner_extra_args(config, wanted)
    callback.apply_scanner_extra_args(config, wanted)
    assert nikto_options(config)["extra_args"] == ["-timeout", "40s", *NIKTO_ARGS]
    assert config["scanners"][1] == {"name": "nuclei"}


def test_absent_scanner_is_not_created() -> None:
    config: dict[str, Any] = {"scanners": [{"name": "nuclei"}]}
    callback.apply_scanner_extra_args(config, {"nikto": ("-maxtime", "40s")})
    assert config == {"scanners": [{"name": "nuclei"}]}
