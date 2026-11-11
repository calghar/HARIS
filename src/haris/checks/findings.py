from typing import Any

from ..core.confidence import _priors
from ..core.vuln_class import get_registry
from ..models import Finding
from ..net import ScopedResponse

TECH_HEADERS = ("server", "x-powered-by", "x-aspnet-version")


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
