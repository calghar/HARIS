import logging
import time
from datetime import UTC, datetime
from typing import Any

from ..models import (
    CorrelatedFinding,
    Finding,
    OwaspCategory,
    RemediationStep,
    RiskPosture,
    ScannerResult,
    ScanSession,
    Severity,
    Target,
)
from .correlator import FindingCorrelator
from .owasp import map_to_owasp
from .remediation import RemediationPlanner
from .risk import assess_risk_posture, risk_posture_summary
from .scanner import BaseScanner

logger = logging.getLogger(__name__)


class ScanEngine:
    """Orchestrates a full security audit.

    Usage::

        engine = ScanEngine(scanners=[WapitiScanner(), SSLyzeScanner()])
        session = engine.run(target, config)
    """

    def __init__(
        self,
        scanners: list[BaseScanner] | None = None,
        session_id: str | None = None,
        template_manager: Any | None = None,
        llm_backend: Any | None = None,
        llm_config: dict[str, Any] | None = None,
    ) -> None:
        self.scanners: list[BaseScanner] = scanners or []
        self.session_id = session_id or datetime.now(UTC).strftime("%Y%m%d-%H%M%S")
        self._correlator = FindingCorrelator()
        self._planner = RemediationPlanner()
        self._template_manager = template_manager
        self._llm_backend = llm_backend
        self._llm_config: dict[str, Any] = llm_config or {}

    def add_scanner(self, scanner: BaseScanner) -> None:
        self.scanners.append(scanner)

    def run(
        self,
        target: Target,
        config: dict[str, Any] | None = None,
    ) -> ScanSession:
        """Execute all registered scanners against *target*.

        Scanners run sequentially to avoid overwhelming the target and
        to respect rate-limit constraints.  After all scanners finish,
        findings are enriched with OWASP mappings, correlated across
        tools, risk-assessed, and remediation is planned.
        """
        config = config or {}
        session = ScanSession(
            session_id=self.session_id,
            target=target,
            started_at=datetime.now(UTC).isoformat(),
        )

        logger.info(
            "Starting audit session %s against %s",
            self.session_id,
            target.base_url,
        )

        for scanner in self.scanners:
            scanner_config = config.get(scanner.name, {})
            self._run_single_scanner(scanner, target, scanner_config, session)

        session.finished_at = datetime.now(UTC).isoformat()
        self._enrich_findings(session)
        self._correlate_findings(session)
        self._assess_risk(session)
        self._plan_remediation(session)

        # Optional LLM-powered enrichment pipeline
        if self._llm_backend and self._llm_config.get("enrichment_enabled"):
            self._llm_enrich(session)

        logger.info(
            "Audit session %s complete — %d findings (%d correlated), "
            "risk posture: %s, %.1fs",
            self.session_id,
            len(session.all_findings),
            len(session.correlated),
            session.risk_posture.value,
            session.duration_seconds,
        )
        return session

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _run_single_scanner(
        self,
        scanner: BaseScanner,
        target: Target,
        scanner_config: dict[str, Any],
        session: ScanSession,
    ) -> None:
        """Run one scanner and collect its results into the session."""
        logger.info("Running scanner: %s", scanner.name)
        session.scanners_used.append(scanner.name)

        try:
            # Merge template-derived options before user config
            if self._template_manager:
                template_opts = self._template_manager.get_scanner_options(
                    scanner.name,
                )
                if template_opts:
                    merged = {**template_opts, **scanner_config}
                    scanner_config = merged

            if scanner_config:
                scanner.configure(scanner_config)

            start = time.monotonic()
            result = scanner.scan(target)
            elapsed = time.monotonic() - start

            result.metadata["elapsed_seconds"] = round(elapsed, 2)
            session.scanner_results.append(result)
            session.all_findings.extend(result.findings)

            if result.errors:
                session.errors.extend(f"[{scanner.name}] {e}" for e in result.errors)

            logger.info(
                "Scanner %s finished: %d findings, %d errors in %.1fs",
                scanner.name,
                len(result.findings),
                len(result.errors),
                elapsed,
            )

        except Exception:
            msg = f"Scanner {scanner.name} failed with an exception"
            logger.exception(msg)
            session.errors.append(msg)

    def _enrich_findings(self, session: ScanSession) -> None:
        """Post-process findings: de-duplicate, tag OWASP, sort."""
        seen_ids: set[str] = set()
        unique: list[Finding] = []

        for finding in session.all_findings:
            if not finding.owasp_category:
                self._auto_map_owasp(finding)

            dedup_key = (finding.title, finding.url, finding.parameter)
            key_str = str(dedup_key)
            if key_str not in seen_ids:
                seen_ids.add(key_str)
                unique.append(finding)

        unique.sort(key=lambda f: f.severity.sort_key)
        session.all_findings = unique

    def _correlate_findings(self, session: ScanSession) -> None:
        """Cross-tool correlation and intelligent de-duplication."""
        session.correlated = self._correlator.correlate(session.all_findings)

    def _assess_risk(self, session: ScanSession) -> None:
        """Compute overall risk posture."""
        session.risk_posture = assess_risk_posture(session.all_findings)
        session.risk_posture_text = risk_posture_summary(session.risk_posture)

    def _plan_remediation(self, session: ScanSession) -> None:
        """Generate a prioritised remediation checklist."""
        session.remediation_steps = self._planner.plan(session.all_findings)

    @staticmethod
    def _auto_map_owasp(finding: Finding) -> None:
        """Try to set owasp_category from tags or title using OWASP 2025 mappings."""
        for tag in finding.tags:
            mapping = map_to_owasp(tag)
            if mapping:
                finding.owasp_category = mapping.category.value
                if not finding.cwe_id and mapping.typical_cwes:
                    finding.cwe_id = mapping.typical_cwes[0]
                return

        title_lower = finding.title.lower().replace(" ", "_")
        mapping = map_to_owasp(title_lower)
        if mapping:
            finding.owasp_category = mapping.category.value
            if not finding.cwe_id and mapping.typical_cwes:
                finding.cwe_id = mapping.typical_cwes[0]

    def _llm_enrich(self, session: ScanSession) -> None:
        """Run LLM-powered enrichment, correlation, and triage."""
        try:
            from ..llm.correlation import LLMCorrelator
            from ..llm.enrichment import FindingEnricher
            from ..llm.router import ModelRouter
            from ..llm.triage import SmartTriager

            if self._llm_backend is None:
                logger.warning("LLM backend is not configured; skipping enrichment")
                return
            routing = self._llm_config.get("model_routing", {})
            router = ModelRouter(self._llm_backend, routing)

            threshold = self._llm_config.get(
                "enrich_severity_threshold",
                "high",
            )
            max_tokens = self._llm_config.get(
                "max_tokens_per_finding",
                1024,
            )

            # 1) Enrich individual findings
            enricher = FindingEnricher(
                router.for_task("enrichment"),
                severity_threshold=threshold,
                max_tokens=max_tokens,
            )
            session.llm_enrichments = enricher.batch_enrich(
                session.all_findings,
                session.target,
            )

            # 2) Identify attack chains
            correlator = LLMCorrelator(
                router.for_task("attack_chains"),
            )
            session.attack_chains = correlator.identify_attack_chains(
                session.all_findings,
            )

            # 3) Smart triage
            triage_ctx = self._llm_config.get("triage_context", {})
            triager = SmartTriager(router.for_task("triage"))
            session.triaged_findings = triager.triage_findings(
                session.all_findings,
                triage_ctx,
            )

            # 4) False positive detection
            fp_correlator = LLMCorrelator(
                router.for_task("false_positives"),
            )
            session.false_positive_assessments = fp_correlator.detect_false_positives(
                session.all_findings,
            )

            # 5) Executive priorities
            session.executive_priorities = triager.generate_executive_priorities(
                session.all_findings,
            )

            logger.info(
                "LLM enrichment complete: %d enrichments, %d attack chains, %d triaged",
                len(session.llm_enrichments),
                len(session.attack_chains),
                len(session.triaged_findings),
            )
        except ImportError:
            logger.warning("LLM enrichment modules not available — skipping")
        except Exception:
            logger.exception("LLM enrichment failed — continuing without it")


# Silence unused-import warnings for names imported solely so
# engine.py remains the single import point for legacy consumers.
__all__ = [
    "CorrelatedFinding",
    "Finding",
    "OwaspCategory",
    "RemediationStep",
    "RiskPosture",
    "ScanEngine",
    "ScannerResult",
    "ScanSession",
    "Severity",
    "Target",
]
