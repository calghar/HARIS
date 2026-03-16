import logging
import os
from pathlib import Path
from typing import Any

import yaml

from ..models import AuthConfig, Config, LLMConfig, ScannerConfig, Scope, Target
from ..models.templates import TemplateSource

logger = logging.getLogger(__name__)

DEFAULT_CONFIG_PATH = (
    Path(__file__).resolve().parent.parent.parent
    / "config"
    / "default_config.yaml"
)


def load_config(
    config_path: str | Path | None = None,
    overrides: dict[str, Any] | None = None,
) -> Config:
    """Load configuration from a YAML file, applying env var overrides.

    Priority (highest to lowest):
    1. ``overrides`` dict
    2. Environment variables (HARIS_*)
    3. YAML config file
    4. Built-in defaults
    """
    raw: dict[str, Any] = {}

    # Load YAML
    path = Path(config_path) if config_path else DEFAULT_CONFIG_PATH
    if path.exists():
        with open(path) as fh:
            raw = yaml.safe_load(fh) or {}
        logger.info("Loaded config from %s", path)
    else:
        logger.warning("Config file not found: %s -- using defaults", path)

    # Apply env var overrides
    _apply_env_overrides(raw)

    # Apply programmatic overrides
    if overrides:
        _deep_merge(raw, overrides)

    return _build_config(raw)


def _apply_env_overrides(raw: dict[str, Any]) -> None:
    """Override config values from environment variables."""
    env_map = {
        "HARIS_TARGET_URL": ("target", "url"),
        "HARIS_AUTH_COOKIE": ("target", "auth", "cookie_value"),
        "HARIS_AUTH_HEADER": ("target", "auth", "header_value"),
        "HARIS_AUTH_USERNAME": ("target", "auth", "username"),
        "HARIS_AUTH_PASSWORD": ("target", "auth", "password"),
        "HARIS_OUTPUT_DIR": ("output_dir",),
        "HARIS_LOG_LEVEL": ("log_level",),
        "HARIS_PROFILE": ("profile",),
        "HARIS_TEMPLATE_DIR": ("template_dir",),
    }

    for env_key, path in env_map.items():
        value = os.environ.get(env_key)
        if value is not None:
            _set_nested(raw, path, value)
            logger.debug("Env override: %s -> %s", env_key, path)


def _build_config(raw: dict[str, Any]) -> Config:
    """Convert raw dict into a Config model."""
    target_raw = raw.get("target", {})

    # Build scope
    scope_raw = target_raw.get("scope", {})
    scope = Scope(
        allowed_domains=scope_raw.get("allowed_domains", []),
        excluded_paths=scope_raw.get("excluded_paths", []),
        max_depth=scope_raw.get("max_depth", 5),
        rate_limit_rps=scope_raw.get("rate_limit_rps", 10.0),
        max_requests=scope_raw.get("max_requests", 10_000),
        allowed_methods=scope_raw.get(
            "allowed_methods", ["GET", "HEAD", "OPTIONS"]
        ),
    )

    # Build auth
    auth_raw = target_raw.get("auth", {})
    auth = AuthConfig(
        method=auth_raw.get("method", "none"),
        cookie_name=auth_raw.get("cookie_name", ""),
        cookie_value=auth_raw.get("cookie_value", ""),
        header_name=auth_raw.get("header_name", "Authorization"),
        header_value=auth_raw.get("header_value", ""),
        login_url=auth_raw.get("login_url", ""),
        username_field=auth_raw.get("username_field", "username"),
        password_field=auth_raw.get("password_field", "password"),
        username=auth_raw.get("username", ""),
        password=auth_raw.get("password", ""),
    )

    target = Target(
        base_url=target_raw.get("url", "https://example.com"),
        scope=scope,
        auth=auth,
        metadata=target_raw.get("metadata", {}),
    )

    # Build scanners
    scanners_raw = raw.get("scanners", [])
    scanners = [
        ScannerConfig(
            name=s.get("name", "unknown"),
            enabled=s.get("enabled", True),
            options=s.get("options", {}),
        )
        for s in scanners_raw
    ]

    # Apply profiles
    profile = raw.get("profile", "full")
    if not scanners:
        scanners = _default_scanners_for_profile(profile)

    # Build template sources
    template_sources_raw = raw.get("template_sources", [])
    template_sources = [
        TemplateSource(**ts) for ts in template_sources_raw
        if isinstance(ts, dict)
    ]

    # Build LLM config
    llm_raw = raw.get("llm", {})
    llm_config = LLMConfig(
        backend=llm_raw.get("backend", "anthropic"),
        model=llm_raw.get("model", ""),
        enrichment_enabled=llm_raw.get("enrichment_enabled", False),
        enrich_severity_threshold=llm_raw.get(
            "enrich_severity_threshold", "high",
        ),
        max_tokens_per_finding=llm_raw.get("max_tokens_per_finding", 1024),
        triage_context=llm_raw.get("triage_context", {}),
    )

    return Config(
        target=target,
        scanners=scanners,
        profile=profile,
        output_dir=raw.get("output_dir", "./reports"),
        report_formats=raw.get("report_formats", ["markdown", "json"]),
        log_level=raw.get("log_level", "INFO"),
        template_dir=raw.get("template_dir", "./templates"),
        template_sources=template_sources,
        llm=llm_config,
    )


def _default_scanners_for_profile(profile: str) -> list[ScannerConfig]:
    """Return the default set of scanners for a given profile."""
    profiles: dict[str, list[ScannerConfig]] = {
        "quick": [
            ScannerConfig("header_checks"),
            ScannerConfig("tls_checks"),
            ScannerConfig("misc_checks"),
        ],
        "full": [
            ScannerConfig("header_checks"),
            ScannerConfig("tls_checks"),
            ScannerConfig("misc_checks"),
            ScannerConfig("nmap"),
            ScannerConfig("sslyze"),
            ScannerConfig("wapiti"),
        ],
        "regression": [
            ScannerConfig("header_checks"),
            ScannerConfig("tls_checks"),
        ],
    }
    return profiles.get(profile, profiles["full"])


def _deep_merge(base: dict, override: dict) -> None:
    """Recursively merge *override* into *base* in place."""
    for key, value in override.items():
        if (
            key in base
            and isinstance(base[key], dict)
            and isinstance(value, dict)
        ):
            _deep_merge(base[key], value)
        else:
            base[key] = value


def _set_nested(d: dict, path: tuple[str, ...], value: Any) -> None:
    """Set a nested dict value by a tuple path."""
    for key in path[:-1]:
        d = d.setdefault(key, {})
    d[path[-1]] = value
