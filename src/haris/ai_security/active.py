import json
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlencode

from ..checks.requesting import is_html, try_request
from ..models import (
    Finding,
    VerificationMethod,
    VerificationOracle,
    VerificationTier,
)
from ..net import ScopedClient, ScopedResponse
from ..verify.evidence import centre, exchange
from ..verify.oracles import INERT_HTML
from .discovery import Endpoint, origin_of
from .findings import ai_finding
from .passive import EVIDENCE_CHARS, JSON_HEADERS
from .probes import Prompt, load_probes, new_canary, new_marker

SKIP_NO_POST = "POST is not an allowed method, so chat probes were skipped"
RATE_LIMIT_HEADER_PARTS = ("ratelimit", "retry-after")


@dataclass
class ActiveSettings:
    max_prompts: int
    max_tokens: int
    markers: list[str] = field(default_factory=list)


@dataclass(frozen=True, eq=False)
class Reply:
    response: ScopedResponse
    text: str
    completion_tokens: int | None

    @property
    def ok(self) -> bool:
        return 200 <= self.response.status_code < 300


class Prompter:
    """Sends prompts to one chat route; each counts against the shared budget."""

    def __init__(
        self, client: ScopedClient, endpoint: Endpoint, left: list[int], max_tokens: int
    ) -> None:
        self.client, self.endpoint, self.max_tokens = client, endpoint, max_tokens
        self._left = left

    def ask(self, content: str, max_tokens: int | None = None) -> Reply | None:
        if self._left[0] <= 0:
            return None
        self._left[0] -= 1
        body: dict[str, Any] = {
            "messages": [{"role": "user", "content": content}],
            "max_tokens": min(max_tokens or self.max_tokens, self.max_tokens),
            "temperature": 0,
        }
        if self.endpoint.models:
            body["model"] = self.endpoint.models[0]
        resp = try_request(
            self.client,
            "POST",
            self.endpoint.chat_url,
            headers=JSON_HEADERS,
            body=json.dumps(body),
        )
        return _reply(resp) if resp is not None else None


def _reply(resp: ScopedResponse) -> Reply:
    try:
        body = json.loads(resp.text)
        choice = body["choices"][0]
        message = choice.get("message", {}).get("content") or choice.get("text")
        tokens = body.get("usage", {}).get("completion_tokens")
    except (ValueError, KeyError, IndexError, TypeError, AttributeError):
        return Reply(resp, "", None)
    ok = 200 <= resp.status_code < 300
    text = message if ok and isinstance(message, str) else ""
    return Reply(resp, text, tokens if isinstance(tokens, int) else None)


def _mark_replay(finding: Finding, confirmed: bool, oracle: VerificationOracle) -> None:
    verification = finding.verification
    verification.method = VerificationMethod.REPLAY
    verification.oracle = oracle
    if confirmed:
        verification.advance(VerificationTier.REPLAY_VERIFIED)


def _canary_finding(prompter: Prompter, prompt: Prompt, kind: str) -> Finding | None:
    """A finding when the model repeats a fresh canary twice running."""
    first_canary = new_canary()
    first = prompter.ask(prompt.content.format(canary=first_canary))
    if first is None or first_canary not in first.text:
        return None
    finding = ai_finding(
        kind,
        url=prompter.endpoint.chat_url,
        method="POST",
        parameter=prompt.id,
        evidence=f"the reply repeated {first_canary}",
        exchanges=[exchange(prompter.client, first.response, "probe", first_canary)],
        digest=prompt.id,
    )
    second_canary = new_canary()
    second = prompter.ask(prompt.content.format(canary=second_canary))
    if second is not None:
        finding.verification.evidence.append(
            exchange(prompter.client, second.response, "probe", second_canary)
        )
    _mark_replay(
        finding,
        second is not None and second_canary in second.text,
        VerificationOracle.CANARY,
    )
    return finding


def _leak_finding(
    prompter: Prompter, prompt: Prompt, markers: list[str]
) -> Finding | None:
    first = prompter.ask(prompt.content)
    if first is None:
        return None
    marker = next((m for m in markers if m in first.text), "")
    if not marker:
        return None
    finding = ai_finding(
        "system_prompt_leak",
        url=prompter.endpoint.chat_url,
        method="POST",
        parameter=prompt.id,
        evidence=" ".join(centre(first.text, marker, EVIDENCE_CHARS).split()),
        exchanges=[exchange(prompter.client, first.response, "probe", marker)],
        digest=prompt.id,
    )
    second = prompter.ask(prompt.content)
    if second is not None:
        finding.verification.evidence.append(
            exchange(prompter.client, second.response, "probe", marker)
        )
    _mark_replay(
        finding, second is not None and marker in second.text, VerificationOracle.CANARY
    )
    return finding


def _limits_signalled(reply: Reply) -> bool:
    names = [h.lower() for h in reply.response.headers]
    return reply.response.status_code == 429 or any(
        part in name for name in names for part in RATE_LIMIT_HEADER_PARTS
    )


def _burst_finding(prompter: Prompter) -> Finding | None:
    probes = load_probes()
    count = probes.ai.burst_requests
    replies = [prompter.ask(probes.consumption.burst.content) for _ in range(count)]
    if any(r is None for r in replies):
        return None
    sent = [r for r in replies if r is not None]
    if not all(r.ok for r in sent) or any(_limits_signalled(r) for r in sent):
        return None
    return ai_finding(
        "missing_rate_limit",
        url=prompter.endpoint.chat_url,
        method="POST",
        evidence=f"{count} requests all returned 2xx, no rate-limit header",
        exchanges=[exchange(prompter.client, sent[-1].response, "probe")],
    )


def _token_cap_finding(prompter: Prompter) -> Finding | None:
    cap = load_probes().consumption.max_tokens
    reply = prompter.ask(cap.content, max_tokens=cap.max_tokens)
    if reply is None or not reply.ok:
        return None
    if reply.completion_tokens is not None:
        ignored = reply.completion_tokens > cap.max_tokens
        size = f"{reply.completion_tokens} tokens"
    else:
        ignored = len(reply.text) > cap.chars_per_token * cap.max_tokens
        size = f"{len(reply.text)} characters"
    if not ignored:
        return None
    return ai_finding(
        "ignored_token_cap",
        url=prompter.endpoint.chat_url,
        method="POST",
        evidence=f"max_tokens={cap.max_tokens} returned {size}",
        exchanges=[exchange(prompter.client, reply.response, "probe")],
    )


def _endpoint_probes(
    prompter: Prompter, markers: list[str], notes: set[str]
) -> list[Finding]:
    probes = load_probes()
    control_canary = new_canary()
    control = prompter.ask(probes.control.content.format(canary=control_canary))
    if control is None or not control.ok:
        notes.add(f"{prompter.endpoint.chat_url} did not answer the control prompt")
        return []
    echoes = control_canary in control.text
    if echoes:
        notes.add(
            f"{prompter.endpoint.chat_url} echoes input, so canary verdicts are void"
        )
    found: list[Finding] = []
    injected: Finding | None = None
    for prompt in probes.probes:
        if prompt.kind == "system_prompt_leak":
            hit = _leak_finding(prompter, prompt, markers) if markers else None
        elif echoes:
            hit = None
        else:
            hit = _canary_finding(prompter, prompt, prompt.kind)
            injected = injected or hit
        found += [hit] if hit else []
    if injected is None and not echoes:
        for prompt in probes.jailbreaks:
            hit = _canary_finding(prompter, prompt, "jailbreak_canary")
            found += [hit] if hit else []
    found += [
        f
        for f in (_burst_finding(prompter), _token_cap_finding(prompter))
        if f is not None
    ]
    return found


def _xss_finding(
    client: ScopedClient, left: list[int], origin: str, path: str, param: str
) -> Finding | None:
    template = load_probes().xss.marker
    url = f"{origin}{path}"
    outcomes: list[ScopedResponse] = []
    for _ in range(2):
        if left[0] <= 0:
            break
        left[0] -= 1
        marker = new_marker(template)
        resp = try_request(client, "GET", f"{url}?{urlencode({param: marker})}")
        live = (
            resp is not None
            and 200 <= resp.status_code < 300
            and is_html(resp)
            and marker in INERT_HTML.sub("", resp.text)
        )
        if not live or resp is None:
            break
        outcomes.append(resp)
    if not outcomes:
        return None
    finding = ai_finding(
        "output_handling_xss",
        url=url,
        parameter=param,
        evidence="the marker came back unescaped in an HTML response",
        exchanges=[exchange(client, r, "probe") for r in outcomes],
    )
    _mark_replay(finding, len(outcomes) == 2, VerificationOracle.REFLECTION)
    return finding


def run_active(
    client: ScopedClient,
    base_url: str,
    endpoints: list[Endpoint],
    settings: ActiveSettings,
    notes: set[str],
) -> list[Finding]:
    """Prompt-sending probes; the caller has checked both authorisation flags."""
    left = [settings.max_prompts]
    markers = list(
        dict.fromkeys([*load_probes().ai.system_prompt_markers, *settings.markers])
    )
    found: list[Finding] = []
    chat = list({e.chat_url: e for e in endpoints if e.chat_url}.values())
    if chat and "POST" not in {m.upper() for m in client.target.scope.allowed_methods}:
        notes.add(SKIP_NO_POST)
        chat = []
    for endpoint in chat:
        prompter = Prompter(client, endpoint, left, settings.max_tokens)
        found += _endpoint_probes(prompter, markers, notes)
    origin = origin_of(base_url)
    for sink in load_probes().xss.sinks:
        hit = _xss_finding(client, left, origin, sink.path, sink.param)
        found += [hit] if hit else []
    return found
