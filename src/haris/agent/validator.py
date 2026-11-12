import secrets
from urllib.parse import quote, urljoin, urlsplit

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
from ..net import NetworkError, ScopedClient, ScopedResponse
from ..verify.oracles import INERT_HTML, MARKER_TAG, is_html
from ..verify.probe import FORM_HEADERS, Prober, VerifyBudgetExhausted, random_token
from ..verify.settings import load_verify_settings
from .models import PoC, PoCRequest
from .proxy import classify_request


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


def _send(prober: Prober, request: PoCRequest, value: str) -> ScopedResponse:
    """Put *value* at ``{marker}`` in the URL and, for POST, in the form body."""
    encoded = quote(value, safe="")
    url = request.url.replace("{marker}", encoded)
    if request.method.upper() != "POST":
        return prober.request(request.method, url)
    body = request.body.replace("{marker}", encoded).encode()
    return prober.request(request.method, url, body=body, headers=dict(FORM_HEADERS))


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
    base = prober.client.target.base_url
    positive = False
    exchanges: list[EvidenceExchange] = []
    for item in poc.requests:
        request = item.model_copy(update={"url": urljoin(f"{base}/", item.url)})
        try:
            live, sent = _run_request(request, finding, prober, allow_unsafe)
        except VerifyBudgetExhausted:
            break
        positive = positive or live
        exchanges += sent
    return positive, exchanges


def _run_request(
    request: PoCRequest, finding: Finding, prober: Prober, allow_unsafe: bool
) -> tuple[bool, list[EvidenceExchange]]:
    """Send one PoC request and its control; True when the oracle is positive."""
    base = prober.client.target.base_url
    outcome, _reason = classify_request(
        request.method,
        request.url,
        request.body,
        allowed_domains=list(prober.client.target.scope.allowed_domains),
        allow_unsafe=allow_unsafe,
        finding_url=urljoin(f"{base}/", finding.url),
        finding_method=finding.method,
    )
    if outcome == "rejects" or not _in_scope(prober.client, request.url):
        return False, []
    marker = fresh_marker()
    payload = f"\"'>{marker}"
    control = random_token(len(payload))
    try:
        probe = _send(prober, request, payload)
        control_response = _send(prober, request, control)
    except NetworkError:
        return False, []
    exchanges = [
        prober.exchange(probe, "poc", marker),
        prober.exchange(control_response, "control"),
    ]
    live = _positive(probe.text, control_response.text, marker, is_html(probe))
    return live, exchanges


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
        poc,
        case,
        Prober(client, load_verify_settings().poc_max_requests),
        allow_unsafe=allow_unsafe,
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
