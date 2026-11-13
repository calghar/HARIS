from pathlib import Path
from typing import Any

import pytest

from haris.cli import main
from haris.core.runner import ScanRunner
from tests.test_engine_pipeline import Probe

URL = ["--url", "https://example.com"]
ACTIVE = {"active": True, "authorised": True}


@pytest.fixture
def seen(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> dict[str, Any]:
    """Run the CLI with a stub scanner and record the options the runner received."""
    record: dict[str, Any] = {"built": False}

    def build(runner: ScanRunner) -> list[Probe]:
        record["built"] = True
        record["options"] = runner._scanner_options
        return [Probe("nuclei")]

    monkeypatch.setattr(ScanRunner, "_build_scanners", build)
    monkeypatch.setattr("haris.cli_scan._save_session_to_db", lambda *_a, **_k: None)
    monkeypatch.chdir(tmp_path)
    return record


def cli(*flags: str) -> int:
    return main([*URL, "--yes", "--formats", "json", "--output", "out", *flags])


def test_ai_active_without_authorisation_exits_3_before_any_scan(seen, capsys) -> None:
    assert cli("--ai-active") == 3
    assert seen["built"] is False
    assert "--i-have-authorization" in capsys.readouterr().err


def test_no_flags_pass_no_ai_options(seen) -> None:
    assert cli() == 0
    assert seen["options"] == {}


def test_authorisation_flag_alone_does_not_activate(seen) -> None:
    assert cli("--i-have-authorization") == 0
    assert seen["options"] == {}


def test_both_flags_activate_the_three_ai_scanners(seen) -> None:
    assert cli("--ai-active", "--i-have-authorization") == 0
    assert seen["options"] == {
        "ai_security": {**ACTIVE, "system_prompt_markers": []},
        "garak": ACTIVE,
        "promptfoo": ACTIVE,
    }


def test_system_prompt_markers_reach_the_ai_check(seen) -> None:
    cli(
        "--ai-active",
        "--i-have-authorization",
        "--ai-system-prompt-marker",
        "ONE",
        "--ai-system-prompt-marker",
        "TWO",
    )
    assert seen["options"]["ai_security"]["system_prompt_markers"] == ["ONE", "TWO"]


def test_declined_interactive_authorisation_exits_3(monkeypatch, seen) -> None:
    monkeypatch.setattr("builtins.input", lambda _prompt="": "no")
    code = main([*URL, "--ai-active", "--i-have-authorization"])
    assert code == 3
    assert seen["built"] is False


def test_ai_security_profile_is_selectable(seen) -> None:
    assert cli("--profile", "ai-security") == 0
