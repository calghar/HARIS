import logging

from ..models import Finding
from ..models.enrichment import AttackChain
from .backend import BaseLLMBackend
from .enrichment_prompts import EnrichmentPromptBuilder
from .schemas import ChainOut, FalsePositiveOut
from .structured import StageReport, run_chunks

logger = logging.getLogger(__name__)


class LLMCorrelator:
    """Uses LLM to find semantic relationships across findings.

    Unlike the deterministic correlator which uses fingerprint matching,
    this class detects higher-level patterns: e.g. XSS + missing CSP
    are related, SQLi + exposed DB port form an attack chain. Verdicts are
    annotations; no method removes or alters a finding. ``last_report``
    records a status for every finding sent, including ``skipped_budget``.
    """

    def __init__(self, backend: BaseLLMBackend) -> None:
        self.backend = backend
        self._prompts = EnrichmentPromptBuilder()
        self.last_report = StageReport()

    def identify_attack_chains(
        self,
        findings: list[Finding],
    ) -> list[AttackChain]:
        """Identify attack chains within each severity-ordered batch of findings."""
        self.last_report = StageReport()
        if len(findings) < 2:
            return []
        known_ids = {f.finding_id for f in findings}
        parsed = run_chunks(
            self.backend,
            findings,
            self.last_report,
            prompt_for=self._prompts.identify_attack_chains,
            model=ChainOut,
            temperature=0.1,
            max_tokens=2048,
        )
        chains = [
            chain
            for i, item in enumerate(parsed, 1)
            if (chain := item.to_model(f"chain_{i}", known_ids)) is not None
        ]
        dropped = len(parsed) - len(chains)
        if dropped:
            self.last_report.errors.append(f"{dropped} chain(s) cite unknown findings")
        return chains

    def detect_false_positives(
        self,
        findings: list[Finding],
    ) -> list[dict[str, str]]:
        """Return validated false-positive assessments; findings are never removed."""
        self.last_report = StageReport()
        if not findings:
            return []
        parsed = run_chunks(
            self.backend,
            findings,
            self.last_report,
            prompt_for=self._prompts.assess_false_positives,
            model=FalsePositiveOut,
            temperature=0.1,
            max_tokens=1024,
        )
        known_ids = {f.finding_id for f in findings}
        for item in parsed:
            if item.finding_id not in known_ids:
                self.last_report.errors.append(f"unknown finding {item.finding_id}")
        return [item.model_dump() for item in parsed]
