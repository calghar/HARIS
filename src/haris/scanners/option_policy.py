import math
from typing import Any
from urllib.parse import urlsplit

from ..ai_security.options import ACTIVE_KEY, AUTHORISED_KEY
from ..net.errors import SSRFBlocked
from ..net.policy import NetworkPolicy
from ..net.ssrf import Resolver, system_resolver, vet_host
from .argv_policy import ExtraArgsError, validate_extra_args
from .option_values import (
    _BOOL,
    _LIST,
    _LIST_ITEM_MAX_CHARS,
    _LIST_MAX_ITEMS,
    _NUMBER,
    _NUMBER_MAX,
    _NUMBER_MIN,
    _POSITIVE_KEYS,
    _STRINGS,
    _TEXT,
    _TEXT_MAX_CHARS,
    _VALUE_KINDS,
)

_GATE_KEYS = frozenset({ACTIVE_KEY, AUTHORISED_KEY})
_URL_SCHEMES = frozenset({"http", "https"})
_BLOCKED_FLAGS = {
    "nuclei": frozenset({"-fr"}),
    "nikto": frozenset({"-followredirects"}),
}
_URL_OPTIONS = {"wapiti": frozenset({"external_endpoint", "internal_endpoint"})}
# Keys scanners read, plus keys built-in templates and the template form already store.
_OPTION_KEYS: dict[str, frozenset[str]] = {
    "nuclei": frozenset(
        {
            "timeout",
            "templates",
            "tags",
            "severity",
            "exclude_tags",
            "rate_limit",
            "max_host_errors",
            "concurrency",
            "bulk_size",
            "template_dirs",
            "extra_args",
            "enable_interactsh",
            "automatic_scan",
            "update_templates",
            "timeout_per_request",
            "retries",
            "phase2_timeout_s",
        }
    ),
    "nikto": frozenset({"timeout", "extra_args", "tuning", "plugins"}),
    "wapiti": frozenset(
        {
            "timeout",
            "max_scan_time",
            "scope",
            "modules",
            "max_links",
            "extra_args",
            "seed_paths",
            "external_endpoint",
            "internal_endpoint",
        }
    ),
    "nmap": frozenset(
        {"ports", "timeout", "extra_args", "nse_scripts", "script_categories"}
    ),
    "sslyze": frozenset({"timeout", "extra_args"}),
    "zap": frozenset(
        {
            "timeout",
            "spider_minutes",
            "passive_minutes",
            "active_minutes",
            "threads",
            "delay_ms",
            "extra_args",
            "max_instances",
        }
    ),
    "header_checks": frozenset({"follow_redirects"}),
    "tls_checks": frozenset({"timeout", "cert_expiry_warn_days"}),
    "misc_checks": frozenset({"check_sensitive_paths", "check_cors", "check_redirect"}),
    "info_disclosure": frozenset(
        {
            "check_error_pages",
            "check_debug_endpoints",
            "check_html_comments",
            "check_version_endpoints",
            "max_body_bytes",
        }
    ),
    "cookie_checks": frozenset({"max_cookie_lifetime_seconds"}),
    # Server and port stay on the CLI; the web must not choose where DNS packets go.
    "dns_checks": frozenset({"dns_timeout"}),
    "ai_security": frozenset(
        {"max_prompts", "max_tokens_per_prompt", "system_prompt_markers"}
    ),
    "garak": frozenset(
        {"timeout", "extra_args", "max_prompts", "max_tokens_per_prompt", "probes"}
    ),
    "promptfoo": frozenset(
        {
            "timeout",
            "extra_args",
            "max_prompts",
            "max_tokens_per_prompt",
            "plugins",
            "provider",
        }
    ),
}


class ScannerOptionsError(ValueError):
    pass


def prepare_web_scanner_options(
    options: object,
    *,
    allow_private: bool | None = None,
    resolver: Resolver = system_resolver,
) -> dict[str, dict[str, Any]]:
    """Reject unknown keys, blocked flags, unsafe URLs, and bad values."""
    if not isinstance(options, dict):
        raise ScannerOptionsError("scanner_options must be an object")
    private = (
        NetworkPolicy.from_env().allow_private
        if allow_private is None
        else allow_private
    )
    cleaned: dict[str, dict[str, Any]] = {}
    for name, raw in options.items():
        if not isinstance(name, str) or not isinstance(raw, dict):
            raise ScannerOptionsError("scanner_options must map names to objects")
        kept = {key: value for key, value in raw.items() if key not in _GATE_KEYS}
        if not kept:
            continue
        allowed = _OPTION_KEYS.get(name)
        if allowed is None:
            raise ScannerOptionsError(f"unknown scanner {name}")
        unknown = sorted(str(key) for key in kept if key not in allowed)
        if unknown:
            raise ScannerOptionsError(f"unknown option {unknown[0]} for {name}")
        for key, value in kept.items():
            _check_value(name, key, value)
        if "extra_args" in kept:
            _check_extra_args(name, kept["extra_args"])
        for key in _URL_OPTIONS.get(name, ()):
            if key in kept:
                _check_url(
                    name, key, kept[key], allow_private=private, resolver=resolver
                )
        cleaned[name] = kept
    return cleaned


def _bad_value(scanner: str, option: object) -> ScannerOptionsError:
    return ScannerOptionsError(f"{scanner}.{option} is not a valid value")


def _check_value(scanner: str, option: object, value: object) -> None:
    kind = _VALUE_KINDS.get(str(option))
    if kind == _NUMBER:
        _check_number(scanner, option, value)
    elif kind == _BOOL and isinstance(value, bool):
        return
    elif kind in {_TEXT, _STRINGS} and isinstance(value, str):
        _check_text(scanner, option, value)
    elif kind in {_LIST, _STRINGS}:
        _check_list(scanner, option, value)
    else:
        raise _bad_value(scanner, option)


def _check_number(scanner: str, option: object, value: object) -> None:
    if (
        isinstance(value, bool)
        or not isinstance(value, int | float)
        or not math.isfinite(value)
        or not _NUMBER_MIN <= value <= _NUMBER_MAX
        or (str(option) in _POSITIVE_KEYS and value <= 0)
    ):
        raise _bad_value(scanner, option)


def _check_text(scanner: str, option: object, value: object) -> None:
    if not isinstance(value, str) or len(value) > _TEXT_MAX_CHARS:
        raise _bad_value(scanner, option)


def _check_list(scanner: str, option: object, value: object) -> None:
    if (
        not isinstance(value, list)
        or len(value) > _LIST_MAX_ITEMS
        or any(
            not isinstance(item, str) or len(item) > _LIST_ITEM_MAX_CHARS
            for item in value
        )
    ):
        raise _bad_value(scanner, option)


def _check_extra_args(scanner: str, args: object) -> None:
    try:
        validate_extra_args(scanner, args)
    except ExtraArgsError as exc:
        raise ScannerOptionsError(f"extra_args for {scanner} are not allowed") from exc
    if not isinstance(args, list):
        return
    blocked = _BLOCKED_FLAGS.get(scanner, frozenset())
    for token in args:
        flag = str(token).split("=", 1)[0]
        if flag in blocked:
            raise ScannerOptionsError(
                f"extra_args flag {flag} is not allowed for {scanner}"
            )


def _check_url(
    scanner: str,
    option: str,
    value: object,
    *,
    allow_private: bool,
    resolver: Resolver,
) -> None:
    if value in ("", None):
        return
    parts = urlsplit(value) if isinstance(value, str) else None
    host = parts.hostname if parts is not None else None
    if parts is None or parts.scheme not in _URL_SCHEMES or not host:
        raise ScannerOptionsError(f"{scanner}.{option} must be an http(s) URL")
    try:
        port = parts.port or (443 if parts.scheme == "https" else 80)
    except ValueError as exc:
        raise ScannerOptionsError(f"{scanner}.{option} must be an http(s) URL") from exc
    try:
        vet_host(host, port, allow_private=allow_private, resolver=resolver)
    except SSRFBlocked as exc:
        raise ScannerOptionsError(f"{scanner}.{option} is not allowed") from exc
