import logging
from typing import Any

from ..models import ScanSession

logger = logging.getLogger(__name__)


def run_llm_enrichment(
    session: ScanSession, backend: Any, llm_config: dict[str, Any]
) -> None:
    """Run LLM-powered enrichment, correlation, and triage."""
    try:
        from ..llm.correlation import LLMCorrelator
        from ..llm.enrichment import FindingEnricher
        from ..llm.router import ModelRouter
        from ..llm.triage import SmartTriager

        if backend is None:
            logger.warning("LLM backend is not configured; skipping enrichment")
            return
        routing = llm_config.get("model_routing", {})
        router = ModelRouter(backend, routing)

        threshold = llm_config.get(
            "enrich_severity_threshold",
            "high",
        )
        max_tokens = llm_config.get(
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
        triage_ctx = llm_config.get("triage_context", {})
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
