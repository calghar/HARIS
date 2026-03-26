"""Scanner configuration data loader.

This module loads scanner configuration data from YAML files to keep
data structures out of scanner implementation code.

Per-scanner configs live in ``config/scanners/{scanner_name}.yaml``.
Cross-scanner shared data lives in ``config/scanner_data.yaml``.
"""

import logging
from pathlib import Path
from typing import Any, cast

import yaml

logger = logging.getLogger(__name__)

_REPO_ROOT = Path(__file__).parent.parent.parent
_SCANNERS_DIR = _REPO_ROOT / "config" / "scanners"

# ---------------------------------------------------------------------------
# Generic per-scanner config loader
# ---------------------------------------------------------------------------

_scanner_config_cache: dict[str, dict[str, Any]] = {}


def _load_scanner_config(scanner_name: str) -> dict[str, Any]:
    """Load ``config/scanners/{scanner_name}.yaml``, cached."""
    if scanner_name in _scanner_config_cache:
        return _scanner_config_cache[scanner_name]

    path = _SCANNERS_DIR / f"{scanner_name}.yaml"
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

    _scanner_config_cache[scanner_name] = data
    return data


# ---------------------------------------------------------------------------
# Nikto helpers
# ---------------------------------------------------------------------------


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


def get_nuclei_meta_tags() -> frozenset[str]:
    """Get Nuclei generic metadata tags (excluded from tech extraction)."""
    tags = _load_scanner_config("nuclei").get("meta_tags", [])
    return frozenset(tags)


def get_nuclei_default_template_dirs() -> list[str]:
    """Get default Nuclei template directories."""
    return cast(
        list[str], _load_scanner_config("nuclei").get("default_template_dirs", [])
    )


def get_nuclei_tech_fingerprint_dir() -> str:
    """Get Nuclei technology fingerprinting directory."""
    return cast(
        str,
        _load_scanner_config("nuclei").get("tech_fingerprint_dir", "http/technologies"),
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


def get_nuclei_remediation_map() -> dict[str, str]:
    """Get OWASP tag → remediation guidance mapping."""
    return cast(
        dict[str, str], _load_scanner_config("nuclei").get("remediation_map", {})
    )


# ---------------------------------------------------------------------------
# Cross-scanner shared data (from config/scanner_data.yaml)
# ---------------------------------------------------------------------------

_shared_data_cache: dict[str, Any] | None = None


def _load_shared_data() -> dict[str, Any]:
    """Load config/scanner_data.yaml, cached."""
    global _shared_data_cache
    if _shared_data_cache is not None:
        return _shared_data_cache

    path = _REPO_ROOT / "config" / "scanner_data.yaml"
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
