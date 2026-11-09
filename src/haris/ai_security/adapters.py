import functools
import os
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, ConfigDict, Field

from ..config.paths import resolve_config_file
from ..models import Finding, ScanContext, ScannerResult, Target
from .discovery import Endpoint, discovery_for
from .findings import AI_TAG, CLASS_PREFIX
from .owasp_ai import load_mappings, risk_label

CONFIDENCE_FLOOR = 0.5
CONFIDENCE_CAP = 0.95
EVIDENCE_CHARS = 300
PRIVATE_MODE = 0o600
REMEDIATION = "Harden the system prompt, filter inputs and outputs, then re-run."
SKIP_INACTIVE = "needs --ai-active and --i-have-authorization"
SKIP_NO_ENDPOINT = "no AI chat endpoint was discovered"
SKIP_NO_CLIENT = "no scan HTTP client is available to discover endpoints"


class ToolConfig(BaseModel):
    model_config = ConfigDict(frozen=True, extra="ignore")

    default_selection: list[str]
    allowed_selection: list[str]
    request_timeout: int = 20
    purpose: str = ""
    env: dict[str, str] = Field(default_factory=dict)


@functools.cache
def tool_config(tool: str) -> ToolConfig:
    """``config/scanners/<tool>.yaml`` (``./config`` override, else packaged)."""
    with open(resolve_config_file(f"scanners/{tool}.yaml"), encoding="utf-8") as fh:
        return ToolConfig.model_validate(yaml.safe_load(fh))


def selection(tool: str, requested: Any) -> list[str]:
    """Requested probes or plugins, else the defaults; others raise ValueError."""
    config = tool_config(tool)
    if requested is None:
        return list(config.default_selection)
    if not isinstance(requested, list) or not requested:
        raise ValueError(f"{tool} selection must be a non-empty list")
    unknown = [r for r in requested if r not in config.allowed_selection]
    if unknown:
        raise ValueError(
            f"{tool} selection {unknown} is not allowed; "
            f"allowed: {', '.join(config.allowed_selection)}"
        )
    return list(requested)


def skipped(scanner: str, reason: str) -> ScannerResult:
    """An empty result that records why the scanner did nothing."""
    return ScannerResult(scanner_name=scanner, metadata={"skipped": [reason]})


def fail_confidence(fails: int, total: int) -> float:
    """``min(0.95, 0.5 + 0.5 * r)`` for fail rate ``r = fails / total``."""
    return min(
        CONFIDENCE_CAP, CONFIDENCE_FLOOR + (1 - CONFIDENCE_FLOOR) * fails / total
    )


def chat_endpoint(target: Target, context: ScanContext | None) -> Endpoint | None:
    """The first discovered endpoint with a chat route, else ``None``."""
    client = context.http if context else None
    if client is None:
        return None
    return next((e for e in discovery_for(client, target) if e.chat_url), None)


def chat_body(endpoint: Endpoint, placeholder: str, max_tokens: int) -> dict[str, Any]:
    body: dict[str, Any] = {
        "messages": [{"role": "user", "content": placeholder}],
        "max_tokens": max_tokens,
    }
    if endpoint.models:
        body["model"] = endpoint.models[0]
    return body


def write_private(path: Path, text: str) -> None:
    """Write *text* readable by the owner only; config files may hold credentials."""
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, PRIVATE_MODE)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write(text)


def tool_finding(
    tool: str,
    key: str,
    *,
    url: str,
    label: str,
    fails: int,
    total: int,
    parameter: str,
    evidence: str,
    raw_data: dict[str, Any],
) -> Finding:
    """One finding for a tool result whose *fails* out of *total* were positive."""
    mappings = load_mappings()
    mapping = mappings.tool_mapping(tool, key)
    return Finding(
        title=f"{tool}: {label} failed in {fails} of {total} tests",
        description=(
            f"{tool} sent {total} tests for {label}; {fails} showed the weakness. "
            "The result comes from the tool and has not been confirmed by a replay."
        ),
        severity=mapping.severity,
        confidence_score=fail_confidence(fails, total),
        owasp_category=risk_label(mapping.owasp[0]),
        cwe_id=mapping.cwe,
        url=url,
        method="POST",
        parameter=parameter,
        evidence=evidence[:EVIDENCE_CHARS],
        remediation=REMEDIATION,
        references=mappings.reference_urls(mapping.owasp),
        scanner=tool,
        vuln_class=CLASS_PREFIX + tool,
        tags=[AI_TAG, tool, *mapping.owasp],
        raw_data=raw_data,
    )
