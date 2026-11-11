import logging

from ..models import Finding, Target
from .backend import BaseLLMBackend
from .budget import BudgetExceededError
from .enrichment_prompts import EnrichmentPromptBuilder
from .schemas import VariantOut
from .structured import STATUS_SKIPPED_BUDGET, StageReport, call_structured

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
        self.last_report = StageReport()

    def suggest_variants(
        self,
        finding: Finding,
        target: Target,
    ) -> list[VariantSuggestion]:
        """Return variant suggestions for a confirmed finding."""
        self.last_report = StageReport()
        system, prompt = self._prompts.suggest_variants(finding, target)
        try:
            result = call_structured(
                self.backend,
                prompt,
                system=system,
                model=VariantOut,
                many=True,
                temperature=0.3,
                max_tokens=1024,
            )
        except BudgetExceededError as exc:
            self.last_report.statuses[finding.finding_id] = STATUS_SKIPPED_BUDGET
            self.last_report.errors.append(str(exc))
            return []
        except Exception:
            logger.warning(
                "Variant analysis failed for %s", finding.finding_id, exc_info=True
            )
            return []
        self.last_report.errors.extend(result.errors)
        return [VariantSuggestion(**item.model_dump()) for item in result.items]
