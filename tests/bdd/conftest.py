import subprocess
import sys
from pathlib import Path

import pytest
import yaml
from pytest_bdd import given, parsers, then, when

ROOT = Path(__file__).resolve().parents[2]
MAPS = Path(__file__).parent / "maps"
FEATURES = Path(__file__).resolve().parents[1] / "features"
_RUNS: dict[tuple[str, ...], tuple[int, str]] = {}


def load_map(feature: str) -> dict[str, dict[str, object]]:
    merged: dict[str, dict[str, object]] = {}
    for path in sorted(MAPS.glob(f"{feature}*.yaml")):
        merged |= yaml.safe_load(path.read_text()) or {}
    return merged


# pytest-bdd sets each scenario function's __doc__ to "<feature file path>: <scenario>"
def entry_for(doc: str) -> dict[str, object]:
    feature, _, scenario = doc.partition(": ")
    return load_map(Path(feature).stem).get(scenario, {})


def pytest_collection_modifyitems(items: list[pytest.Item]) -> None:
    for item in items:
        if Path(__file__).parent not in item.path.parents:
            continue
        doc = getattr(getattr(item, "function", None), "__doc__", None)
        if not doc or ": " not in doc or "pending" not in entry_for(doc):
            continue
        item.add_marker(
            pytest.mark.xfail(
                raises=NotImplementedError,
                strict=True,
                reason=f"pending task {entry_for(doc)['pending']}",
            )
        )


def run_targets(targets: list[str]) -> tuple[int, str]:
    key = tuple(targets)
    if key not in _RUNS:
        command = [sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider"]
        done = subprocess.run(  # noqa: S603
            [*command, "-o", "addopts=", *targets],
            cwd=ROOT,
            capture_output=True,
            text=True,
            check=False,
        )
        _RUNS[key] = (done.returncode, done.stdout[-2000:])
    return _RUNS[key]


@given(parsers.re(r".*"))
@when(parsers.re(r".*"))
def _setup_and_trigger_are_in_the_mapped_tests() -> None:
    return None


@then(parsers.re(r".*"))
def _outcome_is_the_mapped_tests(request: pytest.FixtureRequest) -> None:
    entry = entry_for(request.node.function.__doc__)
    assert entry, "no map entry for this scenario"
    if "pending" in entry:
        raise NotImplementedError(f"pending task {entry['pending']}")
    code, output = run_targets(list(entry["tests"]))  # type: ignore[call-overload]
    assert code == 0, output
