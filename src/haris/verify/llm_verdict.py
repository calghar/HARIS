import contextlib
import logging
from collections.abc import Iterator
from typing import Literal

from pydantic import BaseModel, Field

from ..core.confidence import rescore
from ..llm.backend import BaseLLMBackend
from ..llm.budget import BudgetExceededError, LLMBudget
from ..llm.parsing import ParseResult
from ..llm.settings import BudgetSettings
from ..llm.structured import call_structured, run_bounded
from ..models import CorrelatedFinding, LLMAssessment, VerificationTier
from .settings import LLMVerdictSettings, VerifySettings
from .verdict_prompt import (
    MAX_RATIONALE_CHARS,
    MAX_SPAN_CHARS,
    SYSTEM,
    build_prompt,
    exchange_text,
)

logger = logging.getLogger(__name__)

SPAN_QUOTE_CHARS = 120


class SpanOut(BaseModel):
    exchange_index: int = Field(ge=0)
    text: str = Field(min_length=1, max_length=MAX_SPAN_CHARS)


class VerdictOut(BaseModel):
    case_id: str
    verdict: Literal["confirmed", "likely_fp", "inconclusive"]
    confidence: float = Field(ge=0.0, le=1.0)
    cited_spans: list[SpanOut] = Field(min_length=1, max_length=5)
    rationale: str = Field(default="", max_length=MAX_RATIONALE_CHARS)


def eligible(case: CorrelatedFinding) -> bool:
    """Unverified, not suppressed, and with exchanges to cite."""
    finding = case.canonical
    return (
        finding.verification.tier == VerificationTier.UNVERIFIED
        and finding.suppression is None
        and bool(finding.verification.evidence)
    )


def invalid(model: str, reason: str) -> LLMAssessment:
    return LLMAssessment(
        verdict="inconclusive", status="invalid", model=model, rationale=reason
    )


def assess(
    case_id: str,
    texts: list[str],
    result: ParseResult[VerdictOut],
    cfg: LLMVerdictSettings,
    model: str,
) -> LLMAssessment:
    """Validate one model answer against the exchanges it was shown."""
    if not result.items:
        return invalid(model, "; ".join(result.errors) or "no verdict returned")
    out = result.items[0]
    if out.case_id != case_id:
        return invalid(model, "case_id does not match the case")
    for position, span in enumerate(out.cited_spans):
        index = span.exchange_index
        field = f"cited_spans.{position}"
        quote = repr(span.text[:SPAN_QUOTE_CHARS])
        if index >= len(texts):
            return invalid(
                model, f"{field}.exchange_index {index} has no exchange: {quote}"
            )
        if span.text not in texts[index]:
            return invalid(model, f"{field}.text is not in exchange {index}: {quote}")
    return LLMAssessment(
        verdict=out.verdict,
        confidence=out.confidence,
        cited_spans=[s.text for s in out.cited_spans],
        model=model,
        rationale=out.rationale,
        status="abstained" if out.confidence < cfg.abstain_below else "ok",
    )


def judge(
    case: CorrelatedFinding, backend: BaseLLMBackend, cfg: LLMVerdictSettings
) -> tuple[LLMAssessment | None, str]:
    """One case: its assessment, or None with the error when the call failed."""
    finding = case.canonical
    texts = [exchange_text(e, cfg) for e in finding.verification.evidence]
    prompt = build_prompt(finding.finding_id, finding, texts)
    logger.debug(
        "LLM verdict %s: exchange text lengths %s",
        finding.finding_id,
        [len(t) for t in texts],
    )
    try:
        result = call_structured(
            backend,
            prompt,
            system=SYSTEM,
            model=VerdictOut,
            many=False,
            temperature=cfg.temperature,
            max_tokens=cfg.max_output_tokens,
        )
    except BudgetExceededError as exc:
        logger.info("LLM budget spent at %s: %s", finding.finding_id, exc)
        return LLMAssessment(status="skipped_budget", model=backend.model), ""
    except Exception as exc:
        logger.warning("LLM verdict for %s failed", finding.finding_id, exc_info=True)
        return None, f"{finding.finding_id}: {type(exc).__name__}: {exc}"
    logger.debug("LLM verdict %s: raw reply %s", finding.finding_id, result.raw)
    assessment = assess(finding.finding_id, texts, result, cfg, backend.model)
    if assessment.status == "invalid":
        logger.debug(
            "LLM verdict %s: validation error %s",
            finding.finding_id,
            assessment.rationale,
        )
    return assessment, ""


@contextlib.contextmanager
def scoped_budget(backend: BaseLLMBackend, cfg: LLMVerdictSettings) -> Iterator[None]:
    """Cap this stage's tokens and cost; the backend's own budget returns after."""
    previous = backend.budget
    backend.budget = LLMBudget(
        BudgetSettings(max_tokens=cfg.max_tokens, max_cost_usd=cfg.max_cost_usd)
    )
    try:
        yield
    finally:
        backend.budget = previous


def store(case: CorrelatedFinding, assessment: LLMAssessment) -> None:
    """Annotate and rescore; the tier is never touched here."""
    verification = case.canonical.verification
    verification.llm = assessment
    if assessment.status == "ok":
        verification.verdict_source = f"llm:{assessment.model}"
    rescore(case)


def run_llm_verdicts(
    cases: list[CorrelatedFinding], backend: BaseLLMBackend, settings: VerifySettings
) -> list[str]:
    """Judge eligible cases by severity then score; returns error messages."""
    cfg = settings.llm
    ranked = sorted(
        (c for c in cases if eligible(c)),
        key=lambda c: (c.canonical.severity.sort_key, -c.canonical.confidence_score),
    )
    for case in ranked[cfg.max_cases :]:
        store(case, LLMAssessment(status="skipped_budget", model=backend.model))
    batch = ranked[: cfg.max_cases]
    with scoped_budget(backend, cfg):
        outcomes = run_bounded(lambda c: judge(c, backend, cfg), batch)
    errors = []
    for case, (assessment, error) in zip(batch, outcomes, strict=True):
        if assessment is not None:
            store(case, assessment)
        if error:
            errors.append(error)
    return errors
