import importlib.util
from pathlib import Path
from types import ModuleType

ROOT = Path(__file__).resolve().parents[1]


def _load() -> ModuleType:
    spec = importlib.util.spec_from_file_location(
        "check_litellm", ROOT / "scripts/check_litellm.py"
    )
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


check = _load()
GOOD_FILE = {"hash": "sha256:abc"}


def _lock(version: str = "1.108.0", files: list[dict] | None = None) -> dict:
    return {
        "package": [
            {"name": "litellm", "version": version, "wheels": files or [GOOD_FILE]}
        ]
    }


def _manifest(**overrides: object) -> dict:
    data: dict = {
        "project": {
            "dependencies": ["httpx"],
            "optional-dependencies": {"llm": ["litellm==1.108.0"]},
        }
    }
    data["project"].update(overrides)
    return data


def test_repository_passes() -> None:
    assert check.main(ROOT) == 0


def test_exact_pin_passes() -> None:
    assert check.check_manifest(_manifest()) == []


def test_range_pin_fails() -> None:
    manifest = _manifest(**{"optional-dependencies": {"llm": ["litellm>=1.108"]}})
    assert check.check_manifest(manifest)


def test_main_dependency_fails() -> None:
    assert check.check_manifest(_manifest(dependencies=["litellm==1.108.0"]))


def test_other_extra_fails() -> None:
    extras = {"llm": ["litellm==1.108.0"], "web": ["litellm==1.108.0"]}
    assert check.check_manifest(_manifest(**{"optional-dependencies": extras}))


def test_missing_pin_fails() -> None:
    assert check.check_manifest(_manifest(**{"optional-dependencies": {"llm": []}}))


def test_clean_lock_passes() -> None:
    assert check.check_lock(_lock()) == []


def test_denied_versions_fail() -> None:
    for version in ("1.82.7", "1.82.8", "1.107.0"):
        assert check.check_lock(_lock(version))


def test_unhashed_file_fails() -> None:
    assert check.check_lock(_lock(files=[GOOD_FILE, {"url": "x"}]))


def test_missing_entry_fails() -> None:
    assert check.check_lock({"package": []})
