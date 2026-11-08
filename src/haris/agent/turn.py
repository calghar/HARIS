import logging

from ..llm.backend import BaseLLMBackend, ProviderBackend
from ..llm.budget import BudgetExceededError, LLMBudget
from ..llm.redaction import fence, new_nonce
from ..llm.structured import call_structured
from ..models import CorrelatedFinding, Target
from .audit import AuditLog, digest
from .budget import llm_budget
from .models import PoC, PoCRequest, Review, ToolCall
from .prompts import REVIEW_SYSTEM
from .settings import AgentSettings

logger = logging.getLogger(__name__)

REVIEW_TOKENS = 200
ANNOTATION_CAP = 500


def fence_text(text: str) -> str:
    try:
        return fence(text, new_nonce())
    except ValueError:
        return fence(text, new_nonce())


def prompt_for(case: CorrelatedFinding, transcript: list[str]) -> str:
    finding = case.canonical
    summary = (
        f"class={finding.vuln_class} method={finding.method} "
        f"url={finding.url} parameter={finding.parameter}\n{finding.description}"
    )
    body = fence_text(summary)
    if transcript:
        body = body + "\n" + "\n".join(transcript[-8:])
    return body


def poc_from(step: ToolCall) -> PoC | None:
    raw = step.arguments.get("poc", "")
    if raw:
        return PoC.model_validate_json(raw)
    url = step.arguments.get("url", "")
    if not url:
        return None
    return PoC(
        requests=[
            PoCRequest(
                method=step.arguments.get("method", "GET"),
                url=url,
                body=step.arguments.get("body", ""),
            )
        ],
        oracle=step.arguments.get("oracle", ""),
        expected_span=step.arguments.get("expected_span", ""),
    )


def review_poc(backend: BaseLLMBackend, poc: PoC | None, audit: AuditLog) -> None:
    """Separate context, no tools. The reply is recorded and then ignored."""
    if poc is None:
        return
    try:
        parsed = call_structured(
            backend,
            fence_text(poc.model_dump_json()),
            system=REVIEW_SYSTEM,
            model=Review,
            many=False,
            temperature=0,
            max_tokens=REVIEW_TOKENS,
        )
    except BudgetExceededError:
        audit.write("kill", reason="tokens")
        return
    except Exception as exc:
        logger.info("Validation review failed: %s", exc)
        return
    notes = parsed.items[0].notes if parsed.items else ""
    audit.write("review", notes=notes, digest=digest(notes))


def proxy_target(target: Target, settings: AgentSettings, unsafe: bool) -> Target:
    methods = ["GET", "HEAD", "OPTIONS", *(["POST"] if unsafe else [])]
    scope = target.scope.model_copy(
        update={
            "rate_limit_rps": settings.rate_limit_rps,
            "max_requests": settings.max_requests,
            "allowed_methods": methods,
        }
    )
    return target.model_copy(update={"scope": scope})


def attach_budget(
    backend: BaseLLMBackend, settings: AgentSettings, spent: float
) -> LLMBudget | None:
    if isinstance(backend, ProviderBackend):
        backend.budget = llm_budget(
            settings, remaining_cost=settings.max_cost_usd - spent
        )
    return backend.budget


def remember(case: CorrelatedFinding, text: str) -> None:
    if text:
        case.canonical.raw_data["agent_annotation"] = text[:ANNOTATION_CAP]


def cancelled(cancel: object | None) -> bool:
    return bool(cancel is not None and getattr(cancel, "is_set", lambda: False)())
