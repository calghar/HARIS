import json
import logging
from typing import Any

from ..models import Finding, Target
from .base import BaseLLMBackend
from .enrichment_prompts import EnrichmentPromptBuilder

logger = logging.getLogger(__name__)


class VariantSuggestion:
    """A suggested variant vulnerability to investigate."""

    __slots__ = ("description", "rationale", "url_pattern")

    def __init__(
        self,
        description: str = "",
        rationale: str = "",
        url_pattern: str = "",
    ) -> None:
        self.description = description
        self.rationale = rationale
        self.url_pattern = url_pattern

    def to_dict(self) -> dict[str, str]:
        return {
            "description": self.description,
            "rationale": self.rationale,
            "url_pattern": self.url_pattern,
        }


class VariantAnalyzer:
    """Suggests similar vulnerabilities to check based on confirmed findings.

    Returns informational suggestions only — does not trigger automated
    scanning or send requests to the target.
    """

    def __init__(self, backend: BaseLLMBackend) -> None:
        self.backend = backend
        self._prompts = EnrichmentPromptBuilder()

    def suggest_variants(
        self,
        finding: Finding,
        target: Target,
    ) -> list[VariantSuggestion]:
        """Return variant suggestions for a confirmed finding."""
        system, prompt = self._prompts.suggest_variants(finding, target)

        try:
            response = self.backend.complete(
                prompt,
                system=system,
                temperature=0.3,
                max_tokens=1024,
            )
            return self._parse_suggestions(response.text)
        except Exception:
            logger.warning(
                "Variant analysis failed for %s", finding.finding_id,
                exc_info=True,
            )
            return []

    @staticmethod
    def _parse_suggestions(raw_text: str) -> list[VariantSuggestion]:
        """Parse LLM JSON into VariantSuggestion objects."""
        try:
            text = raw_text.strip()
            if text.startswith("```"):
                text = text.split("\n", 1)[1]
                text = text.rsplit("```", 1)[0]

            data: list[dict[str, Any]] = json.loads(text)
            return [
                VariantSuggestion(
                    description=item.get("description", ""),
                    rationale=item.get("rationale", ""),
                    url_pattern=item.get("url_pattern", ""),
                )
                for item in data
            ]
        except (json.JSONDecodeError, TypeError):
            logger.warning("Could not parse variant suggestions")
            return []
