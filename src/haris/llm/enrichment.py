import logging

from pydantic import BaseModel, Field

from ..models import Finding, Target
from ..models.enrichment import EnrichedFinding
from .backend import BaseLLMBackend
from .budget import BudgetExceededError
from .enrichment_prompts import EnrichmentPromptBuilder
from .schemas import EnrichmentOut
from .structured import (
    SEVERITY_RANK,
    STATUS_FAILED,
    STATUS_INVALID,
    STATUS_OK,
    STATUS_SKIPPED_BUDGET,
    StageReport,
    call_structured,
    run_bounded,
)

logger = logging.getLogger(__name__)


class EnrichmentBatch(BaseModel):
    items: dict[str, EnrichedFinding] = Field(default_factory=dict)
    report: StageReport = Field(default_factory=StageReport)


class FindingEnricher:
    """Enriches findings with LLM-generated context.

    Only findings at or above *severity_threshold* are enriched to
    manage API token costs. ``last_report`` records a status for every
    finding attempted, including ``skipped_budget``.
    """

    def __init__(
        self,
        backend: BaseLLMBackend,
        severity_threshold: str = "high",
        max_tokens: int = 1024,
    ) -> None:
        self.backend = backend
        self._threshold_rank = SEVERITY_RANK.get(severity_threshold, 1)
        self._max_tokens = max_tokens
        self._prompts = EnrichmentPromptBuilder()
        self.last_report = StageReport()

    def should_enrich(self, finding: Finding) -> bool:
        """Return True if finding severity meets the threshold."""
        rank = SEVERITY_RANK.get(finding.severity.value, 4)
        return rank <= self._threshold_rank

    def _enrich(
        self,
        finding: Finding,
        target: Target,
        sibling_titles: list[str],
    ) -> tuple[EnrichedFinding | None, str, list[str]]:
        system, prompt = self._prompts.enrich_finding(finding, target, sibling_titles)
        try:
            result = call_structured(
                self.backend,
                prompt,
                system=system,
                model=EnrichmentOut,
                many=False,
                temperature=0.1,
                max_tokens=self._max_tokens,
            )
        except BudgetExceededError as exc:
            return None, STATUS_SKIPPED_BUDGET, [str(exc)]
        except Exception as exc:
            logger.warning(
                "Failed to enrich finding %s", finding.finding_id, exc_info=True
            )
            return None, STATUS_FAILED, [f"{finding.finding_id}: {exc}"]
        if not result.items:
            errors = [f"{finding.finding_id}: {e}" for e in result.errors]
            return None, STATUS_INVALID, errors
        return result.items[0].to_model(finding.finding_id), STATUS_OK, []

    def enrich_finding(
        self,
        finding: Finding,
        target: Target,
        sibling_titles: list[str] | None = None,
    ) -> EnrichedFinding | None:
        """Enrich a single finding; None when skipped, failed or unparseable."""
        if not self.should_enrich(finding):
            return None
        return self._enrich(finding, target, sibling_titles or [])[0]

    def run_batch(self, findings: list[Finding], target: Target) -> EnrichmentBatch:
        """Enrich every qualifying finding with bounded concurrency."""
        sibling_titles = [f.title for f in findings]
        selected = [f for f in findings if self.should_enrich(f)]
        outcomes = run_bounded(
            lambda f: self._enrich(f, target, sibling_titles), selected
        )
        batch = EnrichmentBatch()
        for finding, (enriched, status, errors) in zip(selected, outcomes, strict=True):
            batch.report.statuses[finding.finding_id] = status
            batch.report.errors.extend(errors)
            if enriched is not None:
                batch.items[finding.finding_id] = enriched
        self.last_report = batch.report
        return batch

    def batch_enrich(
        self,
        findings: list[Finding],
        target: Target,
    ) -> dict[str, EnrichedFinding]:
        """Enrich all qualifying findings, returning a dict keyed by ID."""
        return self.run_batch(findings, target).items
