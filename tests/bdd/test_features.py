import re

import pytest
from pytest_bdd import scenarios

from tests.bdd.conftest import FEATURES, MAPS, ROOT, load_map

scenarios("../features")

SCENARIO_RE = re.compile(r"^\s*Scenario(?: Outline)?: (.+?)\s*$", re.MULTILINE)
FEATURE_NAMES = sorted(path.stem for path in FEATURES.glob("*.feature"))


@pytest.mark.parametrize("feature", FEATURE_NAMES)
def test_every_scenario_has_one_map_entry(feature: str) -> None:
    names = SCENARIO_RE.findall((FEATURES / f"{feature}.feature").read_text())
    mapped = load_map(feature)
    assert sorted(names) == sorted(mapped), "map and feature scenarios differ"
    for name, entry in mapped.items():
        assert ("tests" in entry) != ("pending" in entry), f"{name}: tests xor pending"


@pytest.mark.parametrize("feature", FEATURE_NAMES)
def test_mapped_tests_exist_outside_the_bdd_package(feature: str) -> None:
    for name, entry in load_map(feature).items():
        for target in entry.get("tests", []):  # type: ignore[attr-defined]
            path = ROOT / str(target).split("::")[0]
            assert path.is_file(), f"{name}: {target} does not exist"
            assert MAPS.parent not in path.parents, f"{name}: {target} in tests/bdd"
