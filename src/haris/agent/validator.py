import secrets
from urllib.parse import quote, urlsplit

from ..core.confidence import rescore
from ..core.vuln_class import get_registry
from ..models import (
    CorrelatedFinding,
    EvidenceExchange,
    Finding,
    VerificationMethod,
    VerificationOracle,
    VerificationTier,
)
from ..net import NetworkError, ScopedClient
from ..verify.oracles import INERT_HTML, MARKER_TAG, is_html
from ..verify.probe import Prober, random_token
from .models import PoC

POC_REQUESTS = 8
SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})


def fresh_marker() -> str:
    return f"<{MARKER_TAG}{secrets.token_hex(4)}>"


def _positive(probe_text: str, control_text: str, marker: str, html: bool) -> bool:
    live = marker in INERT_HTML.sub("", probe_text)
    return html and live and marker not in control_text


def _in_scope(client: ScopedClient, url: str) -> bool:
    parts = urlsplit(url)
    return parts.scheme in {"http", "https"} and client.target.scope.is_url_in_scope(
        url
    )


def _method_ok(method: str, url: str, *, allow_unsafe: bool, finding: Finding) -> bool:
    verb = method.upper()
    if verb in SAFE_METHODS:
        return True
    return bool(
        allow_unsafe
        and verb == "POST"
        and finding.method.upper() == "POST"
        and url == finding.url
    )


def reexecute(
    poc: PoC,
    case: CorrelatedFinding,
    prober: Prober,
    *,
    allow_unsafe: bool,
) -> tuple[bool, list[EvidenceExchange]]:
    """Send the PoC with a fresh marker. The model's own span is not trusted."""
    finding = case.canonical
    cls = get_registry().classes.get(finding.vuln_class)
    if cls is None or not poc.requests or poc.oracle != cls.oracle:
        return False, []
    if poc.oracle != "reflection":
        return False, []
    request = poc.requests[0]
    if not _method_ok(
        request.method, request.url, allow_unsafe=allow_unsafe, finding=finding
    ):
        return False, []
    if not _in_scope(prober.client, request.url):
        return False, []
    marker = fresh_marker()
    payload = f"\"'>{marker}"
    probe_url = request.url.replace("{marker}", quote(payload, safe=""))
    control_url = request.url.replace(
        "{marker}", quote(random_token(len(payload)), safe="")
    )
    try:
        probe = prober.request(request.method, probe_url)
        control = prober.request(request.method, control_url)
    except NetworkError:
        return False, []
    exchanges = [
        prober.exchange(probe, "poc", marker),
        prober.exchange(control, "control"),
    ]
    return _positive(probe.text, control.text, marker, is_html(probe)), exchanges


def apply_validation(
    case: CorrelatedFinding,
    poc: PoC | None,
    client: ScopedClient,
    *,
    model: str,
    allow_unsafe: bool,
) -> str:
    """Advance only when re-execution fires the class oracle. Returns an annotation."""
    if poc is None or not poc.requests:
        return ""
    positive, exchanges = reexecute(
        poc, case, Prober(client, POC_REQUESTS), allow_unsafe=allow_unsafe
    )
    if not positive:
        return "poc re-execution was not confirmed"
    try:
        oracle = VerificationOracle(poc.oracle)
    except ValueError:
        return "poc re-execution was not confirmed"
    verification = case.canonical.verification
    verification.advance(VerificationTier.EXPLOIT_VALIDATED)
    verification.method = VerificationMethod.AGENT
    verification.oracle = oracle
    verification.evidence = exchanges
    verification.verdict_source = f"agent:{model}"
    rescore(case)
    return ""
