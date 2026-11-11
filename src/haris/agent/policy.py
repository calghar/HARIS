import os
from collections.abc import Mapping
from contextvars import ContextVar, Token
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from ..core.exit_codes import EXIT_USAGE
from ..models import CorrelatedFinding, Severity, VerificationTier
from .settings import AgentSettings, load_agent_settings

DISABLED_ENV = "HARIS_AGENT_DISABLED"
CANDIDATE_TIERS = frozenset(
    {VerificationTier.UNVERIFIED, VerificationTier.REPLAY_VERIFIED}
)


class AgentPolicy(BaseModel):
    """Whether this scan may run the agent, and the limits of that run."""

    model_config = ConfigDict(frozen=True)

    authorized: bool
    allow_unsafe_methods: bool = False
    output_dir: str = "output"
    source: Literal["cli", "web"] = "cli"
    settings: AgentSettings = Field(default_factory=load_agent_settings)

    @property
    def runs(self) -> bool:
        return self.authorized and not disabled()


_CURRENT: ContextVar[AgentPolicy | None] = ContextVar(
    "haris_agent_policy", default=None
)


def disabled(environ: Mapping[str, str] | None = None) -> bool:
    env = os.environ if environ is None else environ
    return env.get(DISABLED_ENV) == "1"


def bind_policy(policy: AgentPolicy | None) -> Token[AgentPolicy | None]:
    return _CURRENT.set(policy)


def reset_policy(token: Token[AgentPolicy | None]) -> None:
    _CURRENT.reset(token)


def current_policy() -> AgentPolicy | None:
    policy = _CURRENT.get()
    if policy is None or not policy.runs:
        return None
    return policy


def activation_result(flags: str, env: str) -> str:
    """Map the activation matrix to ``exit 3``, ``agent stage runs`` or skipped."""
    parts = set(flags.split())
    agent = "--agent" in parts
    authorised = "--i-have-authorization" in parts
    if agent and not authorised:
        return "exit 3"
    if agent and authorised and env != f"{DISABLED_ENV}=1":
        return "agent stage runs"
    return "agent stage skipped"


def bind_cli(args: object) -> int | None:
    """Bind the CLI policy. ``--agent`` without authorisation returns exit 3."""
    agent = bool(getattr(args, "agent", False))
    authorised = bool(getattr(args, "i_have_authorization", False))
    if agent and not authorised:
        return EXIT_USAGE
    if not agent or disabled():
        bind_policy(None)
        return None
    bind_policy(
        AgentPolicy(
            authorized=True,
            allow_unsafe_methods=bool(
                getattr(args, "agent_allow_unsafe_methods", False)
            ),
            output_dir=str(getattr(args, "output", None) or "output"),
            source="cli",
        )
    )
    return None


def policy_for_web(
    *,
    is_admin: bool,
    target_authorised: bool,
    output_dir: str,
    allow_unsafe_methods: bool = False,
) -> AgentPolicy | None:
    """Web hook: admin role and a verified target authorisation, both required."""
    if disabled() or not is_admin or not target_authorised:
        return None
    return AgentPolicy(
        authorized=True,
        allow_unsafe_methods=allow_unsafe_methods,
        output_dir=output_dir,
        source="web",
    )


def select_candidates(
    cases: list[CorrelatedFinding], settings: AgentSettings
) -> list[CorrelatedFinding]:
    """Non-suppressed, medium-or-higher, in-class, not already settled."""
    floor = Severity(settings.min_severity).sort_key
    chosen: list[CorrelatedFinding] = []
    allowed = set(settings.classes)
    for case in cases:
        finding = case.canonical
        if finding.suppression is not None or finding.vuln_class not in allowed:
            continue
        if finding.verification.tier not in CANDIDATE_TIERS:
            continue
        if finding.severity.sort_key > floor:
            continue
        chosen.append(case)
    return chosen[: settings.max_jobs]
