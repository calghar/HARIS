from collections.abc import Mapping
from typing import Any

CALLBACK_SERVICE = "callback"
CALLBACK_CONTAINER_PORT = 9090
CALLBACK_HEALTH_PATH = "/health"
WAPITI_SCANNER = "wapiti"


def wapiti_endpoints(published_url: str) -> dict[str, str]:
    """The target reaches the service by name, Wapiti by its published port."""
    return {
        "external_endpoint": f"http://{CALLBACK_SERVICE}:{CALLBACK_CONTAINER_PORT}/",
        "internal_endpoint": f"{published_url}/",
    }


def apply_wapiti_endpoints(config: dict[str, Any], options: dict[str, str]) -> None:
    """Merge `options` into the wapiti entry of a HARIS config mapping."""
    for scanner in config.get("scanners", []):
        if scanner.get("name") == WAPITI_SCANNER:
            scanner.setdefault("options", {}).update(options)


def apply_scanner_extra_args(
    config: dict[str, Any], extra_args: Mapping[str, tuple[str, ...]]
) -> None:
    """Append `extra_args` to the `options.extra_args` of each named scanner entry."""
    for scanner in config.get("scanners", []):
        wanted = list(extra_args.get(scanner.get("name"), ()))
        if not wanted:
            continue
        options = scanner.setdefault("options", {})
        current: list[str] = options.get("extra_args", [])
        span = len(wanted)
        if all(current[i : i + span] != wanted for i in range(len(current))):
            options["extra_args"] = [*current, *wanted]
