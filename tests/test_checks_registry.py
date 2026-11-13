import importlib
import inspect
import pathlib
import pkgutil
import re

import pytest
import yaml

import haris.checks as checks
from haris.config.paths import resolve_config_file
from haris.core.decorators import all_registered, check_registry
from haris.core.scanner import BaseScanner
from haris.scanners import SCANNER_REGISTRY

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


def test_every_concrete_check_class_is_in_check_registry():
    defined = {}
    for info in pkgutil.iter_modules(checks.__path__):
        module = importlib.import_module(f"{checks.__name__}.{info.name}")
        for _, cls in inspect.getmembers(module, inspect.isclass):
            if (
                issubclass(cls, BaseScanner)
                and cls.__module__ == module.__name__
                and not inspect.isabstract(cls)
                and "name" in vars(cls)
            ):
                defined[cls.name] = cls
    assert defined, "no check classes found"
    assert defined == checks.CHECK_REGISTRY


@pytest.mark.parametrize(
    "registry", [SCANNER_REGISTRY, checks.CHECK_REGISTRY], ids=["scanners", "checks"]
)
def test_registry_keys_are_the_class_names(registry):
    assert {key: cls.name for key, cls in registry.items()} == {
        key: key for key in registry
    }


def test_registry_readers_cover_the_maps_and_ai_security():
    assert set(check_registry()) == {*checks.CHECK_REGISTRY, "ai_security"}
    assert set(all_registered()) == {*SCANNER_REGISTRY, *check_registry()}
