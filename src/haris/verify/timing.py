import statistics

from ..models import Finding
from ..net import ScopedResponse
from .oracles import OracleResult, Outcome
from .probe import Prober, random_token
from .settings import TimingSettings, VerifySettings

MS_PER_S = 1000.0

type Pair = tuple[ScopedResponse, ScopedResponse]


def timing_positive(
    probe_s: list[float], control_s: list[float], delay_s: float, ratio: float
) -> bool:
    """Probes beat every control by ``ratio * delay`` and their median reaches it."""
    gap = min(probe_s) - max(control_s)
    return gap >= ratio * delay_s and statistics.median(probe_s) >= delay_s


def _pair(prober: Prober, finding: Finding, payload: str) -> Pair:
    probe = prober.send(finding, payload)
    return probe, prober.send(finding, random_token(len(payload)))


def _result(prober: Prober, outcome: Outcome, pairs: list[Pair]) -> OracleResult:
    exchanges = [
        prober.exchange(response, role)
        for probe, control in pairs
        for response, role in ((probe, "probe"), (control, "control"))
    ]
    return OracleResult(
        outcome=outcome, exchanges=exchanges, baseline_ref=pairs[-1][1].request_id
    )


def request_cost(cfg: TimingSettings, payloads: list[str]) -> int:
    return 2 * (len(payloads) - 1) + 2 * cfg.pairs


def _run(
    finding: Finding, prober: Prober, cfg: TimingSettings, payloads: list[str]
) -> OracleResult:
    first_series: list[Pair] = []
    for template in payloads:
        payload = template.format(d=f"{cfg.delay_s:g}")
        pairs = [_pair(prober, finding, payload)]
        first_series = first_series or pairs
        probe, control = pairs[0]
        gap_s = (probe.elapsed_ms - control.elapsed_ms) / MS_PER_S
        if gap_s < cfg.min_gap_ratio * cfg.delay_s:
            continue
        pairs += [_pair(prober, finding, payload) for _ in range(cfg.pairs - 1)]
        positive = timing_positive(
            [p.elapsed_ms / MS_PER_S for p, _ in pairs],
            [c.elapsed_ms / MS_PER_S for _, c in pairs],
            cfg.delay_s,
            cfg.min_gap_ratio,
        )
        return _result(prober, "positive" if positive else "inconclusive", pairs)
    return _result(prober, "inconclusive", first_series)


def timing(finding: Finding, prober: Prober, settings: VerifySettings) -> OracleResult:
    return _run(finding, prober, settings.timing, settings.timing.payloads)


def timing_cmd(
    finding: Finding, prober: Prober, settings: VerifySettings
) -> OracleResult:
    return _run(finding, prober, settings.timing, settings.timing.cmd_payloads)
