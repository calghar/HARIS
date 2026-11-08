import json
from collections.abc import Callable

from haris.agent.policy import AgentPolicy
from haris.agent.runtime import FakeRuntime
from haris.agent.settings import AgentSettings, load_agent_settings
from haris.llm.base import BaseLLMBackend
from haris.models import (
    CorrelatedFinding,
    Finding,
    LLMResponse,
    ScanSession,
    Scope,
    Severity,
    Target,
    Verification,
    VerificationTier,
)
from haris.net import NetworkPolicy, ScopedClient


class ScriptedBackend(BaseLLMBackend):
    name = "scripted"
    model = "fake-agent"

    def __init__(self, steps: list[dict[str, object]], tokens: int = 10) -> None:
        self.steps = steps
        self.tokens = tokens
        self.prompts: list[str] = []
        self.systems: list[str] = []
        self.index = 0

    def complete(
        self,
        prompt: str,
        *,
        system: str = "",
        temperature: float = 0.2,
        max_tokens: int = 2048,
    ) -> LLMResponse:
        self.prompts.append(prompt)
        self.systems.append(system)
        step = self.steps[min(self.index, len(self.steps) - 1)]
        self.index += 1
        return LLMResponse(
            text=json.dumps(step),
            model=self.model,
            usage={
                "prompt_tokens": self.tokens,
                "completion_tokens": 0,
                "total_tokens": self.tokens,
            },
        )


class Clock:
    def __init__(self) -> None:
        self.now = 0.0

    def __call__(self) -> float:
        return self.now


def finding(
    url: str,
    *,
    tier: VerificationTier = VerificationTier.REPLAY_VERIFIED,
    vuln_class: str = "xss_reflected",
    description: str = "reflected parameter",
) -> Finding:
    return Finding(
        title="Reflected input",
        description=description,
        severity=Severity.HIGH,
        url=url,
        parameter="q",
        method="GET",
        vuln_class=vuln_class,
        scanner="wapiti",
        verification=Verification(tier=tier),
    )


def session_for(
    url: str, item: Finding | None = None
) -> tuple[ScanSession, ScopedClient]:
    target = Target(
        base_url=url,
        scope=Scope(rate_limit_rps=1000, max_requests=1000),
    )
    client = ScopedClient(target, NetworkPolicy(allow_private=True))
    case = CorrelatedFinding(canonical=item or finding(url), consensus_score=0.5)
    session = ScanSession(
        session_id="agent-test",
        target=target,
        correlated=[case],
    )
    return session, client


def policy_for(
    tmp: str,
    settings: AgentSettings | None = None,
    *,
    unsafe: bool = False,
) -> AgentPolicy:
    return AgentPolicy(
        authorized=True,
        allow_unsafe_methods=unsafe,
        output_dir=tmp,
        settings=settings or load_agent_settings(),
    )


def run(
    session: ScanSession,
    client: ScopedClient,
    backend: BaseLLMBackend,
    policy: AgentPolicy,
    runtime: FakeRuntime,
    clock: Callable[[], float] | None = None,
) -> None:
    from haris.agent.coordinator import run_agent_stage

    run_agent_stage(
        session,
        client,
        backend,
        policy,
        runtime_factory=lambda: runtime,
        clock=clock,
    )
