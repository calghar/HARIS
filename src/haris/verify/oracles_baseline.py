from urllib.parse import urljoin, urlsplit

from ..checks.baseline import PathVerdict, get_baseline
from ..models import Finding, VerificationOracle
from ..net import ScopedResponse
from .oracles import OracleResult, Outcome, register
from .probe import Prober
from .settings import VerifySettings

# Baseline.judge words its catch-all / unstable-host refusal "host is <class> and ...".
HOST_REASON_PREFIX = "host is "
SOFT404_COST = 5  # the probe plus the host's control requests
VALIDATOR_COST = 1  # controls are cached once soft404 has run


def judge(finding: Finding, prober: Prober) -> tuple[ScopedResponse, PathVerdict]:
    """GET the finding's URL and judge it against the host baseline."""
    base_url = prober.client.target.base_url
    path = urlsplit(urljoin(f"{base_url}/", finding.url)).path
    probe = prober.get(finding)
    baseline = get_baseline(prober.client, base_url)
    return probe, baseline.judge(path, probe, prober.timeout_s)


def matched_control(verdict: PathVerdict) -> bool:
    return verdict.oracle == VerificationOracle.SOFT404 and not (
        verdict.reason.startswith(HOST_REASON_PREFIX)
    )


def single(
    prober: Prober, outcome: Outcome, probe: ScopedResponse, span: str = ""
) -> OracleResult:
    return OracleResult(
        outcome=outcome, exchanges=[prober.exchange(probe, "probe", span)]
    )


@register("soft404", lambda _s: SOFT404_COST)
def soft404(finding: Finding, prober: Prober, settings: VerifySettings) -> OracleResult:
    probe, verdict = judge(finding, prober)
    outcome: Outcome = "refuted" if matched_control(verdict) else "inconclusive"
    return single(prober, outcome, probe)


@register("content_validator", lambda _s: VALIDATOR_COST)
def content_validator(
    finding: Finding, prober: Prober, settings: VerifySettings
) -> OracleResult:
    probe, verdict = judge(finding, prober)
    if verdict.oracle == VerificationOracle.CONTENT_VALIDATOR:
        outcome: Outcome = "positive" if verdict.validated else "refuted"
        return single(prober, outcome, probe, verdict.span)
    outcome = "refuted" if matched_control(verdict) else "inconclusive"
    return single(prober, outcome, probe)
