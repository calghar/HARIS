"""Scanner configuration data loader.

This module loads scanner configuration data from YAML files to keep
data structures out of scanner implementation code.

Per-scanner configs live in ``config/scanners/{scanner_name}.yaml``.
Cross-scanner shared data lives in ``config/scanner_data.yaml``.
"""

import logging
from typing import Any, cast

import yaml
from pydantic import BaseModel, Field, ValidationError

from ..config.paths import resolve_config_file

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Generic per-scanner config loader
# ---------------------------------------------------------------------------

_scanner_config_cache: dict[str, dict[str, Any]] = {}


class _NucleiConfig(BaseModel):
    """Lightweight schema for config/scanners/nuclei.yaml. All fields default to
    empty so validation never raises — callers fall back to their own defaults."""

    severity_map: dict[str, str] = Field(default_factory=dict)
    confidence_map: dict[str, str] = Field(default_factory=dict)
    baseline_template_dirs: list[str] = Field(default_factory=list)
    max_selected_tags: int = 10
    deny_tags: list[str] = Field(default_factory=list)
    min_tag_templates: int = 3
    max_tag_templates: int = 300
    tag_map: dict[str, list[str]] = Field(default_factory=dict)
    tech_tag_map: dict[str, list[str]] = Field(default_factory=dict)
    tech_workflow_map: dict[str, str] = Field(default_factory=dict)
    remediation_map: dict[str, str] = Field(default_factory=dict)
    exclude_template_types: list[str] = Field(default_factory=list)
    exclude_template_ids: list[str] = Field(default_factory=list)
    unproxied_template_types: list[str] = Field(default_factory=list)
    phase2_timeout_s: float = 900


def _load_scanner_config(scanner_name: str) -> dict[str, Any]:
    """Load ``config/scanners/{scanner_name}.yaml``, cached."""
    if scanner_name in _scanner_config_cache:
        return _scanner_config_cache[scanner_name]

    path = resolve_config_file(f"scanners/{scanner_name}.yaml")
    try:
        with open(path, encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}
            logger.debug("Loaded scanner config from %s", path)
    except FileNotFoundError:
        logger.warning("Scanner config not found: %s. Using empty config.", path)
        data = {}
    except yaml.YAMLError as exc:
        logger.error("Failed to parse scanner config %s: %s", path, exc)
        data = {}

    if scanner_name == "nuclei":
        data = _validate_nuclei_config(data)
    _scanner_config_cache[scanner_name] = data
    return data


def _validate_nuclei_config(data: dict[str, Any]) -> dict[str, Any]:
    """Validate nuclei config dict. Warns on failure, returns data unchanged."""
    try:
        _NucleiConfig.model_validate(data)
    except ValidationError as exc:
        logger.warning(
            "nuclei.yaml failed schema validation — some config keys may be "
            "wrong type and will fall back to defaults: %s",
            exc,
        )
    return data


# ---------------------------------------------------------------------------
# Nikto helpers
# ---------------------------------------------------------------------------


def get_extra_args_allowlist(scanner_name: str) -> dict[str, int]:
    """Get the ``extra_args`` flags a scanner accepts (flag -> value count)."""
    raw = _load_scanner_config(scanner_name).get("extra_args_allowlist", {})
    return {str(flag): int(arity) for flag, arity in raw.items()}


def get_nikto_severity_map() -> dict[str, str]:
    """Get Nikto severity string → internal Severity name mapping."""
    return cast(dict[str, str], _load_scanner_config("nikto").get("severity_map", {}))


def get_nikto_keyword_rules() -> list[dict[str, Any]]:
    """Get Nikto keyword classification rules.

    Returns a list of dicts each with ``keywords``, ``tags``, ``severity``.
    """
    return cast(
        list[dict[str, Any]], _load_scanner_config("nikto").get("keyword_rules", [])
    )


def get_nikto_osvdb_critical() -> frozenset[str]:
    """Get the set of OSVDB IDs considered critical."""
    entries = _load_scanner_config("nikto").get("osvdb_critical", [])
    return frozenset(str(e) for e in entries)


# ---------------------------------------------------------------------------
# Nmap helpers
# ---------------------------------------------------------------------------


def get_nmap_risky_services() -> dict[str, str]:
    """Get service name → risk reason mapping for exposed services."""
    return cast(dict[str, str], _load_scanner_config("nmap").get("risky_services", {}))


def get_nmap_default_ports() -> str:
    """Get default port list string for nmap scanning."""
    return cast(
        str,
        _load_scanner_config("nmap").get("default_ports", "80,443,8080,8443,8000,8888"),
    )


def get_nmap_default_extra_args() -> list[str]:
    """Get default extra nmap CLI arguments."""
    return cast(
        list[str],
        _load_scanner_config("nmap").get("default_extra_args", ["-sV", "--open"]),
    )


# ---------------------------------------------------------------------------
# SSLyze helpers
# ---------------------------------------------------------------------------


def get_sslyze_deprecated_protocols() -> dict[str, dict[str, str]]:
    """Get deprecated TLS/SSL protocol definitions.

    Returns a dict keyed by SSLyze result key, each value has
    ``proto_name`` and ``severity``.
    """
    return cast(
        dict[str, dict[str, str]],
        _load_scanner_config("sslyze").get("deprecated_protocols", {}),
    )


def get_sslyze_vulnerability_checks() -> dict[str, dict[str, Any]]:
    """Get TLS vulnerability check definitions."""
    return cast(
        dict[str, dict[str, Any]],
        _load_scanner_config("sslyze").get("vulnerability_checks", {}),
    )


# ---------------------------------------------------------------------------
# Wapiti helpers
# ---------------------------------------------------------------------------


def get_wapiti_severity_map() -> dict[int, str]:
    """Get Wapiti integer severity → internal Severity name mapping."""
    raw = _load_scanner_config("wapiti").get("severity_map", {})
    return {int(k): v for k, v in raw.items()}


def get_wapiti_excluded_modules() -> list[str]:
    """Get Wapiti modules dropped: covered by built-in checks, or hanging."""
    return cast(list[str], _load_scanner_config("wapiti").get("excluded_modules", []))


def get_wapiti_category_tags() -> dict[str, list[str]]:
    """Get Wapiti category → OWASP tag list mapping."""
    return cast(
        dict[str, list[str]], _load_scanner_config("wapiti").get("category_tags", {})
    )


# ---------------------------------------------------------------------------
# Nuclei helpers (loaded from config/scanners/nuclei.yaml)
# ---------------------------------------------------------------------------


def get_nuclei_severity_map() -> dict[str, str]:
    """Get Nuclei severity string → internal Severity name mapping."""
    return cast(dict[str, str], _load_scanner_config("nuclei").get("severity_map", {}))


def get_nuclei_confidence_map() -> dict[str, str]:
    """Get Nuclei severity → internal Confidence name mapping."""
    return cast(
        dict[str, str], _load_scanner_config("nuclei").get("confidence_map", {})
    )


def get_nuclei_baseline_template_dirs() -> list[str]:
    """Get the Nuclei template directories of the baseline group."""
    return cast(
        list[str], _load_scanner_config("nuclei").get("baseline_template_dirs", [])
    )


def _nuclei_count(key: str, default: int, minimum: int) -> int:
    value = _load_scanner_config("nuclei").get(key, default)
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        raise ValueError(
            f"scanners.nuclei.{key} must be an integer of at least {minimum}, "
            f"got {value!r}"
        )
    return value


def get_nuclei_max_selected_tags() -> int:
    """Get the most tags the Nuclei tag selector may return."""
    return _nuclei_count("max_selected_tags", 10, 1)


def get_nuclei_min_tag_templates() -> int:
    """Get the fewest templates a tag needs to enter the selector allowlist."""
    return _nuclei_count("min_tag_templates", 3, 1)


def get_nuclei_max_tag_templates() -> int:
    """Get the most templates a tag may carry to enter the selector allowlist."""
    return _nuclei_count("max_tag_templates", 300, get_nuclei_min_tag_templates())


def get_nuclei_deny_tags() -> list[str]:
    """Get the Nuclei tags the selector allowlist never holds."""
    return cast(
        list[str],
        _load_scanner_config("nuclei").get("deny_tags", ["dos", "intrusive", "fuzz"]),
    )


def get_nuclei_tag_map() -> dict[str, list[str]]:
    """Get Nuclei template tag → OWASP tag mapping."""
    return cast(dict[str, list[str]], _load_scanner_config("nuclei").get("tag_map", {}))


def get_nuclei_tech_tag_map() -> dict[str, list[str]]:
    """Get detected technology → Nuclei tags mapping."""
    return cast(
        dict[str, list[str]], _load_scanner_config("nuclei").get("tech_tag_map", {})
    )


def get_nuclei_tech_workflow_map() -> dict[str, str]:
    """Get detected technology → Nuclei workflow file mapping."""
    return cast(
        dict[str, str], _load_scanner_config("nuclei").get("tech_workflow_map", {})
    )


def get_nuclei_exclude_template_types() -> list[str]:
    """Get Nuclei protocol types excluded from every run (``-ept``)."""
    return cast(
        list[str], _load_scanner_config("nuclei").get("exclude_template_types", [])
    )


def get_nuclei_unproxied_template_types() -> list[str]:
    """Get Nuclei protocol types that ignore the egress proxy (``-ept``)."""
    return cast(
        list[str], _load_scanner_config("nuclei").get("unproxied_template_types", [])
    )


def get_nuclei_exclude_template_ids() -> list[str]:
    """Get Nuclei template ids excluded because built-in checks cover them."""
    return cast(
        list[str], _load_scanner_config("nuclei").get("exclude_template_ids", [])
    )


def get_nuclei_phase2_timeout() -> float:
    """Get the total seconds Nuclei Phase 2 (tag group plus baseline group) may run."""
    return check_nuclei_phase2_timeout(
        _load_scanner_config("nuclei").get("phase2_timeout_s", 900)
    )


def check_nuclei_phase2_timeout(value: Any) -> float:
    """Return *value* as seconds; zero, negative and NaN raise ``ValueError``."""
    seconds = float(value)
    if not seconds > 0:
        raise ValueError(
            f"scanners.nuclei.phase2_timeout_s must be greater than 0, got {value!r}"
        )
    return seconds


def get_nuclei_remediation_map() -> dict[str, str]:
    """Get OWASP tag → remediation guidance mapping."""
    return cast(
        dict[str, str], _load_scanner_config("nuclei").get("remediation_map", {})
    )


def get_zap_config() -> dict[str, Any]:
    """Severity map, confidence map, instance cap, and extra-args allow-list."""
    return _load_scanner_config("zap")


# ---------------------------------------------------------------------------
# Cross-scanner shared data (from config/scanner_data.yaml)
# ---------------------------------------------------------------------------

_shared_data_cache: dict[str, Any] | None = None


def _load_shared_data() -> dict[str, Any]:
    """Load config/scanner_data.yaml, cached."""
    global _shared_data_cache
    if _shared_data_cache is not None:
        return _shared_data_cache

    path = resolve_config_file("scanner_data.yaml")
    try:
        with open(path, encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}
            logger.debug("Loaded shared scanner data from %s", path)
    except FileNotFoundError:
        logger.warning("Shared scanner data not found: %s. Using empty config.", path)
        data = {}
    except yaml.YAMLError as exc:
        logger.error("Failed to parse shared scanner data %s: %s", path, exc)
        data = {}

    _shared_data_cache = data
    return data


def get_nikto_tech_keywords() -> list[tuple[str, str]]:
    """Get Nikto technology keyword extraction list.

    Returns:
        List of (keyword_to_search, normalized_tech_name) tuples.
    """
    keywords = _load_shared_data().get("nikto", {}).get("tech_keywords", [])
    return [tuple(kw) for kw in keywords if len(kw) == 2]
