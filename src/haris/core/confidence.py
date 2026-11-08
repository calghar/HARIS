import functools
import math
from collections.abc import Iterable
from typing import Any

import yaml

from ..config.paths import resolve_config_file
from ..models import (
    CorrelatedFinding,
    Finding,
    LLMAssessment,
    VerificationTier,
    confidence_from_score,
)

CONFIDENCE_FILE = "confidence.yaml"
CONSENSUS_CAP = 0.95
REPLAY_FLOOR = 0.9
LLM_CONFIRM_BOOST = 0.15
LLM_CONFIRM_CAP = 0.89
LLM_FP_PENALTY = 0.3
LLM_FP_FLOOR = 0.05


@functools.cache
def _priors() -> tuple[float, dict[str, float]]:
    with open(resolve_config_file(CONFIDENCE_FILE), encoding="utf-8") as fh:
        raw: dict[str, Any] = yaml.safe_load(fh)
    return float(raw["default"]), {k: float(v) for k, v in raw["priors"].items()}


def prior_for(finding: Finding) -> float:
    """The finding's own score if set explicitly, else its source's prior."""
    if "confidence_score" in finding.model_fields_set:
        return finding.confidence_score
    default, priors = _priors()
    return priors.get(finding.scanner, default)


def consensus(priors: Iterable[float]) -> float:
    """Combine one prior per distinct scanner: ``1 - prod(1 - c)``, capped."""
    return min(CONSENSUS_CAP, 1 - math.prod(1 - c for c in priors))


def finalise(
    score: float, tier: VerificationTier, llm: LLMAssessment | None = None
) -> float:
    """Apply the LLM adjustment, then the tier floor (the floor wins)."""
    if llm is not None and llm.status == "ok":
        if llm.verdict == "confirmed":
            score = max(
                score, min(LLM_CONFIRM_CAP, score + LLM_CONFIRM_BOOST * llm.confidence)
            )
        elif llm.verdict == "likely_fp":
            score = min(
                score, max(LLM_FP_FLOOR, score - LLM_FP_PENALTY * llm.confidence)
            )
    if tier == VerificationTier.EXPLOIT_VALIDATED:
        return 1.0
    if tier == VerificationTier.REPLAY_VERIFIED:
        return max(score, REPLAY_FLOOR)
    if tier == VerificationTier.REFUTED:
        return 0.0
    return score


def rescore(correlated: CorrelatedFinding) -> None:
    """Recompute the canonical score after a tier or LLM verdict changed."""
    canonical = correlated.canonical
    canonical.confidence_score = finalise(
        correlated.consensus_score,
        canonical.verification.tier,
        canonical.verification.llm,
    )
    canonical.confidence = confidence_from_score(canonical.confidence_score)
