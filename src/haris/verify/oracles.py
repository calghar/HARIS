import re
import secrets
from collections.abc import Callable
from typing import Literal, NamedTuple

from pydantic import BaseModel

from ..models import EvidenceExchange, Finding
from ..net import ScopedResponse
from .probe import Prober, random_token
from .settings import VerifySettings

type Outcome = Literal["positive", "refuted", "inconclusive"]
type OracleFn = Callable[[Finding, Prober, VerifySettings], OracleResult]

MARKER_TAG = "haris"
HTML_TYPES = frozenset({"text/html", "application/xhtml+xml"})
INERT_HTML = re.compile(r"<!--.*?-->|<script\b.*?</script\s*>", re.DOTALL | re.I)
HEADER_TITLE = re.compile(r"missing\s+(\S+)\s+header", re.I)


class OracleResult(BaseModel):
    outcome: Outcome
    exchanges: list[EvidenceExchange]
    baseline_ref: str = ""


class OracleSpec(NamedTuple):
    run: OracleFn
    cost: Callable[[VerifySettings], int]


ORACLES: dict[str, OracleSpec] = {}


def register(
    name: str, cost: Callable[[VerifySettings], int] = lambda _s: 2
) -> Callable[[OracleFn], OracleFn]:
    """Register an oracle under its ``verification.oracle`` name and request cost."""

    def add(run: OracleFn) -> OracleFn:
        ORACLES[name] = OracleSpec(run, cost)
        return run

    return add


def pair_result(
    prober: Prober,
    outcome: Outcome,
    probe: ScopedResponse,
    control: ScopedResponse,
    span: str = "",
) -> OracleResult:
    return OracleResult(
        outcome=outcome,
        exchanges=[
            prober.exchange(probe, "probe", span),
            prober.exchange(control, "control"),
        ],
        baseline_ref=control.request_id,
    )


def is_html(response: ScopedResponse) -> bool:
    media = response.headers.get("content-type", "").split(";")[0].strip().lower()
    return media in HTML_TYPES


@register("reflection")
def reflection(
    finding: Finding, prober: Prober, settings: VerifySettings
) -> OracleResult:
    marker = f"<{MARKER_TAG}{secrets.token_hex(4)}>"
    payload = f"\"'>{marker}"
    probe = prober.send(finding, payload)
    control = prober.send(finding, random_token(len(payload)))
    live = marker in INERT_HTML.sub("", probe.text)
    positive = is_html(probe) and live and marker not in control.text
    return pair_result(
        prober, "positive" if positive else "inconclusive", probe, control, marker
    )


@register("error_signature")
def error_signature(
    finding: Finding, prober: Prober, settings: VerifySettings
) -> OracleResult:
    probe = prober.send(finding, settings.error_probe)
    control = prober.send(finding, random_token(len(settings.error_probe)))
    span = ""
    for pattern in settings.error_signatures:
        match = re.search(pattern, probe.text)
        if match and not re.search(pattern, control.text):
            span = match.group(0)
            break
    return pair_result(
        prober, "positive" if span else "inconclusive", probe, control, span
    )


def header_name(finding: Finding) -> str:
    if finding.parameter:
        return finding.parameter
    match = HEADER_TITLE.search(finding.title)
    return match.group(1) if match else ""


def header_state(
    response: ScopedResponse, name: str, settings: VerifySettings
) -> Literal["absent", "invalid", "valid"]:
    value = response.headers.get(name, "").strip()
    if not value:
        return "absent"
    pattern = settings.header_valid.get(name.lower())
    return "invalid" if pattern and not re.search(pattern, value) else "valid"


@register("header_presence")
def header_presence(
    finding: Finding, prober: Prober, settings: VerifySettings
) -> OracleResult:
    name = header_name(finding)
    first = prober.get(finding)
    second = prober.get(finding)
    states = {header_state(r, name, settings) for r in (first, second)}
    outcome: Outcome = "inconclusive"
    if name and states <= {"absent", "invalid"}:
        outcome = "positive"
    elif name and states == {"valid"}:
        outcome = "refuted"
    return pair_result(prober, outcome, first, second)


@register("canary")
def canary(finding: Finding, prober: Prober, settings: VerifySettings) -> OracleResult:
    token = secrets.token_hex(8)
    instruction = settings.canary_instruction.format(token=token)
    marker = f"HARIS-CANARY-{token}"
    probe = prober.send(finding, instruction)
    control = prober.send(finding, random_token(len(instruction)))
    positive = marker in probe.text and marker not in control.text
    return pair_result(
        prober, "positive" if positive else "inconclusive", probe, control, marker
    )
