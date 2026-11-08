import json
import logging
from typing import Any

from ..models import Finding, Severity
from ..models.enrichment import TriageContext, TriagedFinding
from .base import BaseLLMBackend
from .enrichment_prompts import EnrichmentPromptBuilder

logger = logging.getLogger(__name__)

_SEVERITY_MAP = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
    "info": Severity.INFO,
}


class SmartTriager:
    """Uses LLM to prioritise findings with business context."""

    def __init__(self, backend: BaseLLMBackend) -> None:
        self.backend = backend
        self._prompts = EnrichmentPromptBuilder()

    def triage_findings(
        self,
        findings: list[Finding],
        triage_context: dict[str, Any] | TriageContext | None = None,
    ) -> list[TriagedFinding]:
        """Triage all findings with LLM-assessed priorities."""
        if not findings:
            return []

        if isinstance(triage_context, dict):
            ctx = TriageContext(**triage_context)
        elif triage_context is None:
            ctx = TriageContext()
        else:
            ctx = triage_context

        system, prompt = self._prompts.triage_findings(findings, ctx)

        try:
            response = self.backend.complete(
                prompt,
                system=system,
                temperature=0.1,
                max_tokens=2048,
            )
            return self._parse_triage(response.text, findings)
        except Exception:
            logger.warning("Smart triage failed", exc_info=True)
            return []

    def generate_executive_priorities(
        self,
        findings: list[Finding],
    ) -> str:
        """Return a plain-text executive priority summary."""
        ctx = TriageContext()
        system, prompt = self._prompts.triage_findings(findings, ctx)
        prompt += (
            "\n\nAlso provide a 3-sentence executive summary of the "
            "top priorities after the JSON array."
        )

        try:
            response = self.backend.complete(
                prompt,
                system=system,
                temperature=0.2,
                max_tokens=2048,
            )
            return response.text
        except Exception:
            logger.warning("Executive priorities failed", exc_info=True)
            return ""

    # Parser

    @staticmethod
    def _parse_triage(
        raw_text: str,
        findings: list[Finding],
    ) -> list[TriagedFinding]:
        """Parse LLM JSON into TriagedFinding objects."""
        severity_by_id = {f.finding_id: f.severity for f in findings}

        try:
            text = raw_text.strip()
            if text.startswith("```"):
                text = text.split("\n", 1)[1]
                text = text.rsplit("```", 1)[0]
            # Handle case where LLM adds commentary after JSON
            if text.startswith("["):
                bracket_end = text.rfind("]")
                if bracket_end > 0:
                    text = text[: bracket_end + 1]

            data: list[dict[str, Any]] = json.loads(text)
            results: list[TriagedFinding] = []

            for item in data:
                fid = item.get("finding_id", "")
                original = severity_by_id.get(fid, Severity.INFO)
                adjusted = _SEVERITY_MAP.get(
                    item.get("adjusted_severity", "").lower(),
                    original,
                )

                results.append(
                    TriagedFinding(
                        finding_id=fid,
                        original_severity=original,
                        adjusted_severity=adjusted,
                        exploitability_score=int(
                            item.get("exploitability_score", 5),
                        ),
                        business_priority=int(
                            item.get("business_priority", 5),
                        ),
                        triage_rationale=item.get("triage_rationale", ""),
                        recommended_timeline=item.get(
                            "recommended_timeline",
                            "",
                        ),
                    )
                )

            return results
        except (TypeError, ValueError):
            logger.warning("Could not parse triage response")
            return []
