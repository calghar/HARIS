import json
import logging
from typing import Any

from ..models import Finding
from ..models.enrichment import AttackChain
from .base import BaseLLMBackend
from .enrichment_prompts import EnrichmentPromptBuilder

logger = logging.getLogger(__name__)


class LLMCorrelator:
    """Uses LLM to find semantic relationships across findings.

    Unlike the deterministic correlator which uses fingerprint matching,
    this class detects higher-level patterns: e.g. XSS + missing CSP
    are related, SQLi + exposed DB port form an attack chain.
    """

    def __init__(self, backend: BaseLLMBackend) -> None:
        self.backend = backend
        self._prompts = EnrichmentPromptBuilder()

    def identify_attack_chains(
        self, findings: list[Finding],
    ) -> list[AttackChain]:
        """Identify attack chains across the provided findings."""
        if len(findings) < 2:
            return []

        system, prompt = self._prompts.identify_attack_chains(findings)

        try:
            response = self.backend.complete(
                prompt,
                system=system,
                temperature=0.1,
                max_tokens=2048,
            )
            return self._parse_chains(response.text)
        except Exception:
            logger.warning("Attack chain analysis failed", exc_info=True)
            return []

    def detect_false_positives(
        self, findings: list[Finding],
    ) -> list[dict[str, str]]:
        """Identify findings likely to be false positives."""
        if not findings:
            return []

        system, prompt = self._prompts.assess_false_positives(findings)

        try:
            response = self.backend.complete(
                prompt,
                system=system,
                temperature=0.1,
                max_tokens=1024,
            )
            return self._parse_json_array(response.text)
        except Exception:
            logger.warning("False positive detection failed", exc_info=True)
            return []

    # ------------------------------------------------------------------
    # Parsers
    # ------------------------------------------------------------------

    @staticmethod
    def _parse_chains(raw_text: str) -> list[AttackChain]:
        """Parse LLM JSON into AttackChain objects."""
        try:
            text = raw_text.strip()
            if text.startswith("```"):
                text = text.split("\n", 1)[1]
                text = text.rsplit("```", 1)[0]

            data: list[dict[str, Any]] = json.loads(text)
            chains: list[AttackChain] = []
            for item in data:
                chains.append(AttackChain(
                    chain_id=item.get("chain_id", ""),
                    name=item.get("name", ""),
                    description=item.get("description", ""),
                    finding_ids=item.get("finding_ids", []),
                    total_impact=item.get("total_impact", ""),
                    likelihood=item.get("likelihood", ""),
                ))
            return chains
        except (json.JSONDecodeError, TypeError):
            logger.warning("Could not parse attack chain response")
            return []

    @staticmethod
    def _parse_json_array(raw_text: str) -> list[dict[str, str]]:
        """Parse a JSON array from LLM response."""
        try:
            text = raw_text.strip()
            if text.startswith("```"):
                text = text.split("\n", 1)[1]
                text = text.rsplit("```", 1)[0]
            return json.loads(text)
        except (json.JSONDecodeError, TypeError):
            return []
