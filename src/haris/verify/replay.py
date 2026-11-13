import logging
from urllib.parse import urljoin, urlsplit

from pydantic import BaseModel, Field

from ..core.confidence import rescore
from ..core.vuln_class import get_registry
from ..models import (
    CorrelatedFinding,
    Finding,
    VerificationMethod,
    VerificationOracle,
    VerificationTier,
)
from ..net import NetworkError, RequestBudgetExceeded, ScopedClient, TransportError
from . import oracles_baseline, timing  # noqa: F401  # importing registers the oracles
from .oracles import ORACLES, OracleResult
from .oracles_active import chain_active
from .probe import NotReplayable, Prober, VerifyBudgetExhausted
from .settings import VerifySettings

logger = logging.getLogger(__name__)

NO_ORACLE = "none"
CAP_REASON = "verify.max_requests reached"


class ReplayReport(BaseModel):
    """Findings left untouched with the reason; ``requests`` is the replay traffic."""

    skipped: dict[str, str] = Field(default_factory=dict)
    requests: int = 0


def _request_path(base_url: str, url: str) -> str:
    # Same join as oracles_baseline.judge: the path is against the target base.
    return urlsplit(urljoin(f"{base_url}/", url)).path


def _soft404_only(case: CorrelatedFinding, base_url: str) -> bool:
    finding = case.canonical
    if not (
        base_url
        and finding.vuln_class.startswith("unclassified:")
        and get_registry().is_external(finding.scanner)
        and finding.method.upper() == "GET"
    ):
        return False
    return _request_path(base_url, finding.url) != "/"


def oracle_names(case: CorrelatedFinding, base_url: str = "") -> list[str]:
    """The class's oracle chain (``oracle:`` is comma separated), in run order."""
    if _soft404_only(case, base_url):
        return ["soft404"]
    cls = get_registry().classes.get(case.canonical.vuln_class)
    names = [n.strip() for n in cls.oracle.split(",")] if cls else []
    names = [n for n in names if n != NO_ORACLE]
    return chain_active(names, case.canonical)


def replayable(
    case: CorrelatedFinding, allowed_methods: set[str], base_url: str
) -> bool:
    finding = case.canonical
    return (
        finding.verification.tier == VerificationTier.UNVERIFIED
        and finding.suppression is None
        and finding.method.upper() in allowed_methods
        and bool(oracle_names(case, base_url))
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


def run_chain(
    finding: Finding, names: list[str], prober: Prober, settings: VerifySettings
) -> tuple[str, OracleResult]:
    """Run oracles until one decides; an unreachable target is inconclusive."""
    for name in names:
        try:
            result = ORACLES[name].run(finding, prober, settings)
        except TransportError as exc:
            logger.warning(
                "Replay of %s could not reach the target: %s", finding.url, exc
            )
            return name, OracleResult(outcome="inconclusive", exchanges=[])
        if result.outcome != "inconclusive":
            break
    return name, result


def replay(
    cases: list[CorrelatedFinding], client: ScopedClient, settings: VerifySettings
) -> ReplayReport:
    """Replay each eligible finding; stop at the request cap, leaving the rest as is."""
    report = ReplayReport()
    prober = Prober(client, settings.max_requests, settings.request_timeout_s)
    base_url = client.target.base_url
    allowed = {m.upper() for m in client.target.scope.allowed_methods}
    pending = [c for c in cases if replayable(c, allowed, base_url)]
    for index, case in enumerate(pending):
        finding_id = case.canonical.finding_id
        names = oracle_names(case, base_url)
        missing = [n for n in names if n not in ORACLES]
        if missing:
            report.skipped[finding_id] = f"oracle {missing[0]} is not available"
            continue
        if prober.used + sum(ORACLES[n].cost(settings) for n in names) > (
            settings.max_requests
        ):
            report.skipped.update(
                {c.canonical.finding_id: CAP_REASON for c in pending[index:]}
            )
            break
        try:
            name, result = run_chain(case.canonical, names, prober, settings)
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
