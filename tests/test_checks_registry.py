import pathlib
import re

import pytest
import yaml

import haris.checks as checks
from haris.config.paths import resolve_config_file
from haris.core.decorators import check_registry

NEW_CHECKS = {
    "sri_checks",
    "cache_checks",
    "method_checks",
    "redirect_checks",
    "graphql_checks",
    "openapi_checks",
    "listing_checks",
    "dns_checks",
}
CHECKS_DIR = pathlib.Path(checks.__file__).parent


def test_every_new_check_is_registered_and_exported():
    registered = check_registry()
    assert set(registered) >= NEW_CHECKS
    for name in NEW_CHECKS:
        assert registered[name].__name__ in checks.__all__


@pytest.mark.parametrize("name", sorted(NEW_CHECKS))
def test_new_check_has_a_configured_prior(name):
    with open(resolve_config_file("confidence.yaml"), encoding="utf-8") as fh:
        priors = yaml.safe_load(fh)["priors"]
    assert [key for key in priors if key.startswith(f"{name}.")]


def test_checks_package_does_not_import_a_raw_http_library():
    pattern = re.compile(r"^\s*(?:import|from)\s+(?:requests|httpx|urllib3)\b", re.M)
    offenders = [
        p.name for p in CHECKS_DIR.glob("*.py") if pattern.search(p.read_text())
    ]
    assert offenders == []
