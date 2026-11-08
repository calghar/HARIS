import logging

from pydantic import BaseModel, Field

from ..core.confidence import rescore
from ..core.vuln_class import get_registry
from ..models import (
    CorrelatedFinding,
    VerificationMethod,
    VerificationOracle,
    VerificationTier,
)
from ..net import NetworkError, RequestBudgetExceeded, ScopedClient
from . import timing  # noqa: F401  # importing registers the timing oracle
from .oracles import ORACLES, OracleResult
from .probe import NotReplayable, Prober, VerifyBudgetExhausted
from .settings import VerifySettings

logger = logging.getLogger(__name__)

NO_ORACLE = "none"
CAP_REASON = "verify.max_requests reached"


class ReplayReport(BaseModel):
    """Findings left untouched with the reason; ``requests`` is the replay traffic."""

    skipped: dict[str, str] = Field(default_factory=dict)
    requests: int = 0


def oracle_name(case: CorrelatedFinding) -> str:
    cls = get_registry().classes.get(case.canonical.vuln_class)
    return cls.oracle if cls else NO_ORACLE


def replayable(case: CorrelatedFinding, allowed_methods: set[str]) -> bool:
    finding = case.canonical
    return (
        finding.verification.tier == VerificationTier.UNVERIFIED
        and finding.suppression is None
        and finding.method.upper() in allowed_methods
        and oracle_name(case) != NO_ORACLE
    )


def apply_result(case: CorrelatedFinding, name: str, result: OracleResult) -> None:
    """Record the replay; the tier moves only through ``Verification.advance``."""
    verification = case.canonical.verification
    verification.method = VerificationMethod.REPLAY
    verification.oracle = VerificationOracle(name)
    verification.evidence = result.exchanges
    verification.baseline_ref = result.baseline_ref
    verification.verdict_source = "deterministic"
    if result.outcome == "positive":
        verification.advance(VerificationTier.REPLAY_VERIFIED)
    elif result.outcome == "refuted":
        verification.advance(VerificationTier.REFUTED)
    else:
        return
    rescore(case)


def replay(
    cases: list[CorrelatedFinding], client: ScopedClient, settings: VerifySettings
) -> ReplayReport:
    """Replay each eligible finding; stop at the request cap, leaving the rest as is."""
    report = ReplayReport()
    prober = Prober(client, settings.max_requests)
    allowed = {m.upper() for m in client.target.scope.allowed_methods}
    pending = [c for c in cases if replayable(c, allowed)]
    for index, case in enumerate(pending):
        finding_id = case.canonical.finding_id
        name = oracle_name(case)
        spec = ORACLES.get(name)
        if spec is None:
            report.skipped[finding_id] = f"oracle {name} is not available"
            continue
        if prober.used + spec.cost(settings) > settings.max_requests:
            report.skipped.update(
                {c.canonical.finding_id: CAP_REASON for c in pending[index:]}
            )
            break
        try:
            result = spec.run(case.canonical, prober, settings)
        except (VerifyBudgetExhausted, RequestBudgetExceeded) as exc:
            report.skipped.update(
                {c.canonical.finding_id: str(exc) for c in pending[index:]}
            )
            break
        except (NotReplayable, NetworkError) as exc:
            logger.info("Replay of %s skipped: %s", finding_id, exc)
            report.skipped[finding_id] = f"{type(exc).__name__}: {exc}"
            continue
        apply_result(case, name, result)
    report.requests = prober.used
    return report
