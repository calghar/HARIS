import hashlib
import ipaddress
import math
import re
from collections import Counter
from urllib.parse import urlsplit

from ..checks.requesting import try_request
from ..models import Finding, Severity, Target
from ..net import ScopedClient
from ..verify.evidence import exchange
from .bundles import Asset
from .discovery import Endpoint
from .findings import ai_finding
from .signatures import load_signatures

PROBE_ORIGIN = "https://haris-cors-probe.invalid"
MALFORMED_BODY = '{"haris":'
JSON_HEADERS = {"Content-Type": "application/json"}
EVIDENCE_CHARS = 120
PROMPT_EVIDENCE_CHARS = 80
MAX_PER_KIND = 5
DIGEST_CHARS = 16
LOOPBACK_NAMES = frozenset({"localhost"})
SKIP_NO_POST = "POST is not an allowed method, so the verbose-error check was skipped"


def shannon(text: str) -> float:
    counts = Counter(text)
    return -sum(n / len(text) * math.log2(n / len(text)) for n in counts.values())


def digest_of(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()[:DIGEST_CHARS]


def _squash(text: str, limit: int) -> str:
    return " ".join(text.split())[:limit]


def endpoint_findings(
    client: ScopedClient, target: Target, endpoints: list[Endpoint]
) -> list[Finding]:
    """A discovery finding per endpoint, plus exposure when no auth is set."""
    open_target = not target.auth.as_headers()
    found: list[Finding] = []
    for ep in endpoints:
        sig = ep.signature
        proof = [exchange(client, ep.response, "probe")]
        found.append(
            ai_finding(
                "endpoint_discovered",
                url=ep.url,
                label=sig.label,
                method=sig.method,
                evidence=_squash(ep.response.text, EVIDENCE_CHARS),
                exchanges=proof,
                digest=sig.id,
            )
        )
        kind = {"chat": "unauthenticated_inference", "admin": "unauthenticated_admin"}
        if open_target and sig.capability in kind:
            found.append(
                ai_finding(
                    kind[sig.capability],
                    url=ep.url,
                    label=sig.label,
                    method=sig.method,
                    severity=sig.exposure_severity,
                    evidence=_squash(ep.response.text, EVIDENCE_CHARS),
                    exchanges=proof,
                    digest=sig.id,
                )
            )
    return found


def _overlaps(span: tuple[int, int], claimed: list[tuple[int, int]]) -> bool:
    return any(span[0] < end and start < span[1] for start, end in claimed)


def _provider_keys(asset: Asset) -> list[Finding]:
    rules = load_signatures()
    claimed: list[tuple[int, int]] = []
    found: list[Finding] = []
    for key in rules.provider_keys:
        for match in re.finditer(key.pattern, asset.text):
            secret = match.group(1)
            if _overlaps(match.span(), claimed):
                continue
            if shannon(secret) < rules.min_key_entropy:
                continue
            claimed.append(match.span())
            prefix = asset.text[match.start() : match.start(1)]
            found.append(
                ai_finding(
                    "provider_key_in_bundle",
                    url=asset.url,
                    label=key.label,
                    evidence=f"{prefix}{secret[:4]}... ({len(secret)} characters)",
                    digest=digest_of(secret),
                )
            )
    return found[:MAX_PER_KIND]


def _text_matches(
    asset: Asset, kind: str, patterns: list[str], limit: int, group: int
) -> list[Finding]:
    found: dict[str, Finding] = {}
    for pattern in patterns:
        for match in re.finditer(pattern, asset.text):
            span = _squash(match.group(group), limit)
            key = digest_of(span)
            if key not in found:
                found[key] = ai_finding(kind, url=asset.url, evidence=span, digest=key)
    return list(found.values())[:MAX_PER_KIND]


def bundle_findings(assets: list[Asset]) -> list[Finding]:
    rules = load_signatures()
    found: list[Finding] = []
    for asset in assets:
        found += _provider_keys(asset)
        found += _text_matches(
            asset,
            "system_prompt_in_bundle",
            rules.system_prompt_patterns,
            PROMPT_EVIDENCE_CHARS,
            1,
        )
        found += _text_matches(
            asset,
            "model_config_in_bundle",
            rules.llm_settings_patterns,
            EVIDENCE_CHARS,
            0,
        )
    return found


def widget_findings(assets: list[Asset]) -> list[Finding]:
    found: list[Finding] = []
    for widget in load_signatures().widgets:
        hit = next((a for a in assets if re.search(widget.pattern, a.text)), None)
        if hit is not None:
            found.append(
                ai_finding(
                    "ai_widget", url=hit.url, label=widget.label, digest=widget.id
                )
            )
    return found


def _chat_endpoints(endpoints: list[Endpoint]) -> list[Endpoint]:
    return list({e.chat_url: e for e in endpoints if e.chat_url}.values())


def verbose_error_findings(
    client: ScopedClient, endpoints: list[Endpoint], notes: set[str]
) -> list[Finding]:
    """Send a body that is not a prompt and look for a stack trace in the error."""
    chat = _chat_endpoints(endpoints)
    if chat and "POST" not in {m.upper() for m in client.target.scope.allowed_methods}:
        notes.add(SKIP_NO_POST)
        return []
    found: list[Finding] = []
    for ep in chat:
        resp = try_request(
            client, "POST", ep.chat_url, headers=JSON_HEADERS, body=MALFORMED_BODY
        )
        if resp is None or resp.status_code < 400:
            continue
        hit = next(
            (
                m
                for pattern in load_signatures().error_signatures
                if (m := re.search(pattern, resp.text))
            ),
            None,
        )
        if hit is not None:
            found.append(
                ai_finding(
                    "verbose_provider_error",
                    url=ep.chat_url,
                    method="POST",
                    evidence=_squash(hit.group(0), EVIDENCE_CHARS),
                    exchanges=[exchange(client, resp, "probe", hit.group(0))],
                    digest=digest_of(hit.group(0)),
                )
            )
    return found


def cors_findings(client: ScopedClient, endpoints: list[Endpoint]) -> list[Finding]:
    found: list[Finding] = []
    for ep in _chat_endpoints(endpoints):
        resp = try_request(
            client,
            "OPTIONS",
            ep.chat_url,
            headers={
                "Origin": PROBE_ORIGIN,
                "Access-Control-Request-Method": "POST",
            },
        )
        if resp is None or not 200 <= resp.status_code < 300:
            continue
        allow = resp.headers.get("access-control-allow-origin", "")
        credentials = (
            resp.headers.get("access-control-allow-credentials", "").lower() == "true"
        )
        if allow != "*" and not (allow == PROBE_ORIGIN and credentials):
            continue
        found.append(
            ai_finding(
                "chat_cors",
                url=ep.chat_url,
                method="OPTIONS",
                severity=Severity.HIGH if credentials and allow != "*" else None,
                evidence=f"Access-Control-Allow-Origin: {allow}"
                + (", Access-Control-Allow-Credentials: true" if credentials else ""),
                exchanges=[exchange(client, resp, "probe")],
                digest=f"{allow}|{credentials}",
            )
        )
    return found


def _is_loopback(url: str) -> bool:
    host = urlsplit(url).hostname or ""
    if host.lower() in LOOPBACK_NAMES:
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def transport_findings(
    client: ScopedClient, endpoints: list[Endpoint]
) -> list[Finding]:
    return [
        ai_finding(
            "plaintext_mcp_transport",
            url=ep.url,
            label=ep.signature.label,
            method=ep.signature.method,
            evidence=f"{ep.signature.label} is served at {ep.url}",
            exchanges=[exchange(client, ep.response, "probe")],
            digest=ep.signature.id,
        )
        for ep in endpoints
        if ep.capability == "mcp"
        and urlsplit(ep.url).scheme == "http"
        and not _is_loopback(ep.url)
    ]


def passive_findings(
    client: ScopedClient,
    target: Target,
    endpoints: list[Endpoint],
    assets: list[Asset],
    notes: set[str],
) -> list[Finding]:
    return [
        *endpoint_findings(client, target, endpoints),
        *bundle_findings(assets),
        *widget_findings(assets),
        *verbose_error_findings(client, endpoints, notes),
        *cors_findings(client, endpoints),
        *transport_findings(client, endpoints),
    ]
