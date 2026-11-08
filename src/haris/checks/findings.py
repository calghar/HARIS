import functools
from typing import Any

import yaml

from ..config.paths import resolve_config_file
from ..core.vuln_class import get_registry
from ..models import Finding
from ..net import ScopedResponse

CONFIDENCE_FILE = "confidence.yaml"
TECH_HEADERS = ("server", "x-powered-by", "x-aspnet-version")


@functools.cache
def _priors() -> tuple[float, dict[str, float]]:
    with open(resolve_config_file(CONFIDENCE_FILE), encoding="utf-8") as fh:
        raw: dict[str, Any] = yaml.safe_load(fh)
    return float(raw["default"]), {k: float(v) for k, v in raw["priors"].items()}


def prior(key: str) -> float:
    """Prior for ``<check>.<kind>`` from ``confidence.yaml`` (else its default)."""
    default, priors = _priors()
    return priors.get(key, default)


def make_finding(check: str, kind: str, vuln_class: str, **fields: Any) -> Finding:
    """Build a finding whose CWE comes from its class and confidence from the YAML."""
    fields.setdefault("cwe_id", get_registry().classes[vuln_class].primary_cwe)
    return Finding(
        scanner=check,
        vuln_class=vuln_class,
        confidence_score=prior(f"{check}.{kind}"),
        **fields,
    )


def tech_headers(resp: ScopedResponse) -> dict[str, str]:
    """Technology headers that the engine copies into ``ScanContext``."""
    return {h: resp.headers[h] for h in TECH_HEADERS if resp.headers.get(h)}
