from typing import Any

from ..core.profiles import PROFILES


def profile_descriptions() -> dict[str, str]:
    return {name: " ".join(p.description.split()) for name, p in PROFILES.items()}


def template_form_data(tpl: dict[str, Any] | None) -> dict[str, Any]:
    """JSON for the template form script (read from `#page-data`)."""
    tpl = tpl or {}
    return {
        "profileScanners": {name: list(p.scanners) for name, p in PROFILES.items()},
        "profileDescriptions": profile_descriptions(),
        "savedBackend": tpl.get("llm_backend") or None,
        "templateId": tpl.get("template_id"),
        "scannerOptions": tpl.get("scanner_options") or None,
    }
