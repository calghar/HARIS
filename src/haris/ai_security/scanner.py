import logging
from typing import Any

from ..checks.probe_scanner import ProbeScanner
from ..models import Finding, ScanContext, ScannerResult, Target
from ..net import ScopedClient
from .active import ActiveSettings, run_active
from .bundles import collect_assets
from .discovery import discover, discovery_for
from .findings import confirm_by_replay
from .mcp_probe import mcp_findings
from .options import active_enabled
from .passive import passive_findings
from .probes import load_probes

logger = logging.getLogger(__name__)


class AiSecurityScanner(ProbeScanner):
    """Finds AI endpoints and MCP servers; sends prompts only when authorised."""

    name = "ai_security"
    description = (
        "AI endpoint discovery, passive AI checks, MCP analysis, active probes"
    )

    def __init__(self, options: dict[str, Any] | None = None) -> None:
        super().__init__(options)
        self._notes: set[str] = set()

    def _detect(self, client: ScopedClient, target: Target) -> list[Finding]:
        endpoints = discover(client, target)
        assets = collect_assets(client, target.base_url)
        return [
            *passive_findings(client, target, endpoints, assets, self._notes),
            *mcp_findings(client, target, endpoints, self._notes),
        ]

    def probe(self, client: ScopedClient, target: Target) -> list[Finding]:
        first = self._detect(client, target)
        findings = confirm_by_replay(first, self._detect(client, target))
        if active_enabled(self.options):
            limits = load_probes().ai
            settings = ActiveSettings(
                max_prompts=int(self.options.get("max_prompts", limits.max_prompts)),
                max_tokens=int(
                    self.options.get(
                        "max_tokens_per_prompt", limits.max_tokens_per_prompt
                    )
                ),
                markers=list(self.options.get("system_prompt_markers", [])),
            )
            findings += run_active(
                client,
                target.base_url,
                discovery_for(client, target),
                settings,
                self._notes,
            )
        return findings

    def scan(self, target: Target, context: ScanContext | None = None) -> ScannerResult:
        self._notes = set()
        result = super().scan(target, context)
        if self._notes:
            result.metadata["skipped"] = sorted(self._notes)
            logger.warning("ai_security: %s", "; ".join(sorted(self._notes)))
        return result
