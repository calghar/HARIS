import logging
import secrets
from collections.abc import Callable
from pathlib import Path
from urllib.parse import urljoin, urlsplit

from ..llm.backend import BaseLLMBackend
from ..llm.budget import BudgetExceededError
from ..llm.parsing import parse_object
from ..models import CorrelatedFinding, ScanSession
from ..net import ScopedClient
from .audit import AuditLog, digest
from .budget import JobBudget
from .guardrails import screen
from .models import JobResult, ToolCall
from .policy import AgentPolicy, select_candidates
from .prompts import SYSTEM
from .proxy import ScopeProxy
from .runtime import RuntimeSpec, SandboxRuntime
from .settings import AgentSettings
from .turn import (
    attach_budget,
    cancelled,
    fence_text,
    poc_from,
    prompt_for,
    proxy_target,
    remember,
    review_poc,
)
from .validator import apply_validation

logger = logging.getLogger(__name__)

REVIEW_TOKENS = 200
STEP_TOKENS = 800


def run_agent_stage(
    session: ScanSession,
    client: ScopedClient,
    backend: BaseLLMBackend | None,
    policy: AgentPolicy,
    *,
    runtime_factory: Callable[[], SandboxRuntime] | None = None,
    cancel: object | None = None,
    clock: Callable[[], float] | None = None,
) -> None:
    """One sandboxed job per candidate. Tiers move only in ``apply_validation``."""
    if backend is None:
        session.errors.append("[agent] skipped: no LLM backend")
        return
    settings = policy.settings
    factory = runtime_factory or (lambda: _docker(settings))
    spent = 0.0
    for case in select_candidates(session.correlated, settings):
        if cancelled(cancel):
            break
        runtime = factory()
        try:
            result = run_job(
                session,
                case,
                client,
                backend,
                policy,
                runtime,
                spent=spent,
                cancel=cancel,
                clock=clock,
            )
        except Exception as exc:
            logger.warning("Agent job failed: %s", exc)
            session.errors.append(f"[agent] {type(exc).__name__}: {exc}")
            continue
        finally:
            runtime.stop()
        remember(session, case, result.annotation)
        if result.status != "completed":
            continue
        note = apply_validation(
            case,
            result.poc,
            client,
            model=backend.model,
            allow_unsafe=policy.allow_unsafe_methods,
        )
        if note:
            claim = result.annotation
            remember(session, case, f"{claim}; {note}" if claim else note)
        if isinstance(runtime, SandboxRuntime) and getattr(backend, "budget", None):
            spent = float(getattr(backend.budget, "used_cost", spent))


def run_job(
    session: ScanSession,
    case: CorrelatedFinding,
    client: ScopedClient,
    backend: BaseLLMBackend,
    policy: AgentPolicy,
    runtime: SandboxRuntime,
    *,
    spent: float,
    cancel: object | None,
    clock: Callable[[], float] | None,
) -> JobResult:
    settings = policy.settings
    job_id = secrets.token_hex(8)
    audit = AuditLog(Path(policy.output_dir) / "agent" / job_id / "audit.jsonl")
    proxy = ScopeProxy(
        proxy_target(session.target, settings, policy.allow_unsafe_methods),
        client.policy,
        allow_unsafe=policy.allow_unsafe_methods,
        finding_url=urljoin(f"{session.target.base_url}/", case.canonical.url),
        finding_method=case.canonical.method,
        audit=audit,
    )
    budget = JobBudget(
        settings,
        clock or budget_clock(),
        llm=attach_budget(backend, settings, spent),
    )
    result = JobResult(job_id=job_id)
    hits = 0
    transcript: list[str] = []
    try:
        proxy_url = proxy.start(runtime.bind_host)
        port = urlsplit(proxy_url).port or 0
        netloc = "proxy:8080" if runtime.tunneled else f"127.0.0.1:{port}"
        sandbox_proxy = proxy.client_url(netloc)
        runtime.start(
            RuntimeSpec(
                name=f"haris-agent-job-{job_id}",
                proxy_url=sandbox_proxy,
                image=settings.image,
                network=f"haris-agent-job-{job_id}",
                upstream=f"host.docker.internal:{port}",
            )
        )
        _loop(
            case,
            backend,
            budget,
            runtime,
            audit,
            result,
            transcript,
            allowed_hosts=set(session.target.scope.allowed_domains),
            cancel=cancel,
            hits=hits,
        )
    finally:
        proxy.close()
        audit.close()
    return result


def budget_clock() -> Callable[[], float]:
    import time

    return time.monotonic


def _loop(
    case: CorrelatedFinding,
    backend: BaseLLMBackend,
    budget: JobBudget,
    runtime: SandboxRuntime,
    audit: AuditLog,
    result: JobResult,
    transcript: list[str],
    *,
    allowed_hosts: set[str],
    cancel: object | None,
    hits: int,
) -> None:
    settings = budget.settings
    while True:
        if cancelled(cancel):
            _abort(audit, runtime, result, "cancel")
            return
        if reason := budget.check_clock():
            _abort(audit, runtime, result, reason)
            return
        prompt = prompt_for(case, transcript)
        audit.write("llm", role="request", digest=digest(prompt))
        try:
            response = backend.complete(
                prompt, system=SYSTEM, temperature=0, max_tokens=STEP_TOKENS
            )
        except BudgetExceededError:
            _abort(audit, runtime, result, "tokens")
            return
        audit.write("llm", role="response", digest=digest(response.text))
        if reason := budget.charge_tokens(dict(response.usage)):
            _abort(audit, runtime, result, reason)
            return
        parsed = parse_object(response.text, ToolCall)
        if not parsed.items:
            hits += 1
            audit.write("guardrail", reason="invalid", rule="schema")
            if hits >= settings.guardrail_abort_at:
                _abort(audit, runtime, result, "guardrail")
                return
            continue
        step = parsed.items[0]
        if step.tool == "submit_poc":
            result.poc = poc_from(step)
            result.annotation = step.claim
            audit.write("tool_call", tool=step.tool, arguments=step.arguments)
            review_poc(backend, result.poc, audit)
            return
        if step.done or not step.tool:
            result.annotation = step.claim
            return
        if reason := budget.request_tool():
            _abort(audit, runtime, result, reason)
            return
        audit.write("tool_call", tool=step.tool, arguments=step.arguments)
        hit = screen(step.tool, step.arguments, allowed_hosts=allowed_hosts)
        if hit is not None:
            hits += 1
            audit.write("guardrail", reason=hit.reason, rule=hit.rule, tool=step.tool)
            if hit.reason == "scope" or hits >= settings.guardrail_abort_at:
                _abort(
                    audit,
                    runtime,
                    result,
                    "scope" if hit.reason == "scope" else "guardrail",
                )
                return
            transcript.append(fence_text(f"blocked: {hit.reason} {hit.rule}"))
            continue
        output = runtime.call(step.tool, step.arguments)
        audit.write("tool_result", tool=step.tool, digest=digest(output))
        if output.startswith("rejected: scope") or output.startswith("rejected: ssrf"):
            _abort(audit, runtime, result, "scope")
            return
        transcript.append(fence_text(output))


def _abort(
    audit: AuditLog, runtime: SandboxRuntime, result: JobResult, reason: str
) -> None:
    result.status = "aborted"
    audit.write("kill", reason=reason)
    runtime.kill()


def _docker(settings: AgentSettings) -> SandboxRuntime:
    from .docker_runtime import DockerRuntime

    return DockerRuntime(settings)
