import logging
from typing import Any

from ..models import Finding
from ..models.enrichment import TriageContext, TriagedFinding
from .backend import BaseLLMBackend
from .budget import BudgetExceededError
from .enrichment_prompts import EnrichmentPromptBuilder
from .schemas import TriageOut
from .settings import load_settings
from .structured import STATUS_SKIPPED_BUDGET, StageReport, by_severity, run_chunks

logger = logging.getLogger(__name__)

EXECUTIVE_SUFFIX = (
    "\n\nAlso provide a 3-sentence executive summary of the "
    "top priorities after the JSON object."
)


class SmartTriager:
    """Uses LLM to prioritise findings with business context.

    ``last_report`` records a status for every finding sent, including
    ``skipped_budget``.
    """

    def __init__(self, backend: BaseLLMBackend) -> None:
        self.backend = backend
        self._prompts = EnrichmentPromptBuilder()
        self.last_report = StageReport()

    def triage_findings(
        self,
        findings: list[Finding],
        triage_context: dict[str, Any] | TriageContext | None = None,
    ) -> list[TriagedFinding]:
        """Triage all findings with LLM-assessed priorities."""
        self.last_report = StageReport()
        if not findings:
            return []

        if isinstance(triage_context, dict):
            ctx = TriageContext(**triage_context)
        elif triage_context is None:
            ctx = TriageContext()
        else:
            ctx = triage_context

        parsed = run_chunks(
            self.backend,
            findings,
            self.last_report,
            prompt_for=lambda chunk: self._prompts.triage_findings(chunk, ctx),
            model=TriageOut,
            temperature=0.1,
            max_tokens=2048,
        )
        severity_by_id = {f.finding_id: f.severity for f in findings}
        triaged: list[TriagedFinding] = []
        for item in parsed:
            original = severity_by_id.get(item.finding_id)
            if original is None:
                self.last_report.errors.append(f"unknown finding {item.finding_id}")
                continue
            triaged.append(item.to_model(original))
        return triaged

    def generate_executive_priorities(
        self,
        findings: list[Finding],
    ) -> str:
        """Summary over the most severe findings; the rest are marked omitted."""
        report = StageReport()
        self.last_report = report
        if not findings:
            return ""
        size = load_settings().limits.batch_size
        ranked = by_severity(findings)
        for omitted in ranked[size:]:
            report.statuses[omitted.finding_id] = "omitted_from_summary"
        system, prompt = self._prompts.triage_findings(ranked[:size], TriageContext())
        try:
            return self.backend.complete(
                prompt + EXECUTIVE_SUFFIX,
                system=system,
                temperature=0.2,
                max_tokens=2048,
            ).text
        except BudgetExceededError as exc:
            report.statuses.update(
                {f.finding_id: STATUS_SKIPPED_BUDGET for f in ranked[:size]}
            )
            report.errors.append(str(exc))
        except Exception:
            logger.warning("Executive priorities failed", exc_info=True)
        return ""
