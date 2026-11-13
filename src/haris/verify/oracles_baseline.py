import posixpath
import re
import secrets
from urllib.parse import urljoin, urlsplit, urlunsplit

from ..checks.baseline import (
    CONTROL_PREFIX,
    CONTROL_TOKEN_BYTES,
    PathVerdict,
    get_baseline,
)
from ..models import Finding, VerificationOracle
from ..net import ScopedResponse
from .oracles import OracleResult, Outcome, pair_result, register
from .probe import Prober
from .settings import VerifySettings

# Baseline.judge words its catch-all / unstable-host refusal "host is <class> and ...".
HOST_REASON_PREFIX = "host is "
SOFT404_COST = 6  # the probe, the host's control requests and the header control
VALIDATOR_COST = 1  # controls are cached once soft404 has run
UNCOMMON_HEADERS = re.compile(r"^Uncommon header\(s\) '([^']+)' found")


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
    if matched_control(verdict):
        return single(prober, "refuted", probe)
    header = UNCOMMON_HEADERS.match(finding.title)
    if header is None:
        return single(prober, "inconclusive", probe)
    base_url = prober.client.target.base_url
    control = prober.request("GET", control_url(base_url, finding.url))
    names = [name.strip() for name in header.group(1).split(",")]
    same = all(
        (value := control.headers.get(name)) is not None
        and value == probe.headers.get(name)
        for name in names
    )
    outcome: Outcome = "refuted" if same else "inconclusive"
    return pair_result(prober, outcome, probe, control)


def control_url(base_url: str, url: str) -> str:
    """A random sibling of *url* with its extension, so the same server rules apply."""
    parts = urlsplit(urljoin(f"{base_url}/", url))
    directory, name = posixpath.split(parts.path)
    token = CONTROL_PREFIX + secrets.token_hex(CONTROL_TOKEN_BYTES)
    path = f"{directory.rstrip('/')}/{token}{posixpath.splitext(name)[1]}"
    return urlunsplit(parts._replace(path=path, query="", fragment=""))


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
