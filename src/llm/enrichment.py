import json
import logging
from typing import Any

from ..models import Finding, Target
from ..models.enrichment import EnrichedFinding
from .base import BaseLLMBackend
from .enrichment_prompts import EnrichmentPromptBuilder

logger = logging.getLogger(__name__)

_SEVERITY_RANK = {
    "critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4,
}


class FindingEnricher:
    """Enriches findings with LLM-generated context.

    Only findings at or above *severity_threshold* are enriched to
    manage API token costs.
    """

    def __init__(
        self,
        backend: BaseLLMBackend,
        severity_threshold: str = "high",
        max_tokens: int = 1024,
    ) -> None:
        self.backend = backend
        self._threshold_rank = _SEVERITY_RANK.get(severity_threshold, 1)
        self._max_tokens = max_tokens
        self._prompts = EnrichmentPromptBuilder()

    def should_enrich(self, finding: Finding) -> bool:
        """Return True if finding severity meets the threshold."""
        rank = _SEVERITY_RANK.get(finding.severity.value, 4)
        return rank <= self._threshold_rank

    def enrich_finding(
        self,
        finding: Finding,
        target: Target,
        sibling_titles: list[str] | None = None,
    ) -> EnrichedFinding | None:
        """Enrich a single finding via LLM.

        Returns None if the LLM call fails or the response can't be parsed.
        """
        if not self.should_enrich(finding):
            return None

        system, prompt = self._prompts.enrich_finding(
            finding, target, sibling_titles or [],
        )

        try:
            response = self.backend.complete(
                prompt,
                system=system,
                temperature=0.1,
                max_tokens=self._max_tokens,
            )
            return self._parse_enrichment(finding.finding_id, response.text)
        except Exception:
            logger.warning(
                "Failed to enrich finding %s", finding.finding_id,
                exc_info=True,
            )
            return None

    def batch_enrich(
        self,
        findings: list[Finding],
        target: Target,
    ) -> dict[str, EnrichedFinding]:
        """Enrich all qualifying findings, returning a dict keyed by ID."""
        sibling_titles = [f.title for f in findings]
        results: dict[str, EnrichedFinding] = {}

        for finding in findings:
            enriched = self.enrich_finding(finding, target, sibling_titles)
            if enriched is not None:
                results[finding.finding_id] = enriched

        return results

    @staticmethod
    def _parse_enrichment(
        finding_id: str, raw_text: str,
    ) -> EnrichedFinding | None:
        """Parse LLM JSON response into an EnrichedFinding."""
        try:
            # Strip markdown fences if present
            text = raw_text.strip()
            if text.startswith("```"):
                text = text.split("\n", 1)[1]
                text = text.rsplit("```", 1)[0]

            data: dict[str, Any] = json.loads(text)
            return EnrichedFinding(
                finding_id=finding_id,
                attack_narrative=data.get("attack_narrative", ""),
                business_impact_assessment=data.get(
                    "business_impact_assessment", "",
                ),
                exploitation_complexity=data.get(
                    "exploitation_complexity", "",
                ),
                false_positive_likelihood=data.get(
                    "false_positive_likelihood", "",
                ),
                related_cwes=data.get("related_cwes", []),
                attack_chain_position=data.get("attack_chain_position", ""),
                variant_suggestions=data.get("variant_suggestions", []),
            )
        except (json.JSONDecodeError, KeyError):
            logger.warning(
                "Could not parse enrichment for %s", finding_id,
            )
            return None
