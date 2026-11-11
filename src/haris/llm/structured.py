import logging
from collections.abc import Callable, Sequence
from concurrent.futures import ThreadPoolExecutor
from typing import Any

from pydantic import BaseModel, Field

from ..models import Finding
from .backend import BaseLLMBackend, ProviderBackend
from .budget import BudgetExceededError
from .parsing import ParseResult, array_schema, parse_items, parse_object
from .settings import load_settings

logger = logging.getLogger(__name__)

STATUS_OK = "ok"
STATUS_INVALID = "invalid"
STATUS_FAILED = "failed"
STATUS_SKIPPED_BUDGET = BudgetExceededError.status

SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


class StageReport(BaseModel):
    """Per-finding outcome of one LLM stage; nothing is dropped without a status."""

    statuses: dict[str, str] = Field(default_factory=dict)
    errors: list[str] = Field(default_factory=list)

    def ids_with(self, status: str) -> list[str]:
        return [fid for fid, st in self.statuses.items() if st == status]

    @property
    def skipped_budget(self) -> list[str]:
        return self.ids_with(STATUS_SKIPPED_BUDGET)


def by_severity(findings: Sequence[Finding]) -> list[Finding]:
    return sorted(findings, key=lambda f: SEVERITY_RANK.get(f.severity.value, 4))


def chunked(findings: Sequence[Finding], size: int) -> list[list[Finding]]:
    return [list(findings[i : i + size]) for i in range(0, len(findings), size)]


def call_structured[T: BaseModel](
    backend: BaseLLMBackend,
    prompt: str,
    *,
    system: str,
    model: type[T],
    many: bool,
    temperature: float,
    max_tokens: int,
) -> ParseResult[T]:
    """One call; provider structured output when supported, always validated."""
    kwargs: dict[str, Any] = {
        "system": system,
        "temperature": temperature,
        "max_tokens": max_tokens,
    }
    if isinstance(backend, ProviderBackend):
        schema = array_schema(model) if many else model.model_json_schema()
        response = backend.complete(prompt, response_schema=schema, **kwargs)
    else:
        response = backend.complete(prompt, **kwargs)
    return (parse_items if many else parse_object)(response.text, model)


def run_bounded[A, R](func: Callable[[A], R], items: Sequence[A]) -> list[R]:
    workers = min(load_settings().runtime.max_concurrency, max(1, len(items)))
    with ThreadPoolExecutor(max_workers=workers) as pool:
        return list(pool.map(func, items))


def run_chunks[T: BaseModel](
    backend: BaseLLMBackend,
    findings: Sequence[Finding],
    report: StageReport,
    *,
    prompt_for: Callable[[list[Finding]], tuple[str, str]],
    model: type[T],
    temperature: float,
    max_tokens: int,
) -> list[T]:
    """Severity-ordered chunks; one failed chunk does not affect the others."""
    size = load_settings().limits.batch_size

    def one(chunk: list[Finding]) -> tuple[list[Finding], list[T], str, list[str]]:
        system, prompt = prompt_for(chunk)
        try:
            result = call_structured(
                backend,
                prompt,
                system=system,
                model=model,
                many=True,
                temperature=temperature,
                max_tokens=max_tokens,
            )
        except BudgetExceededError as exc:
            return chunk, [], STATUS_SKIPPED_BUDGET, [str(exc)]
        except Exception as exc:
            logger.warning("LLM chunk failed", exc_info=True)
            return chunk, [], STATUS_FAILED, [f"{type(exc).__name__}: {exc}"]
        status = STATUS_INVALID if result.errors and not result.items else STATUS_OK
        return chunk, result.items, status, result.errors

    items: list[T] = []
    for chunk, parsed, status, errors in run_bounded(
        one, chunked(by_severity(findings), size)
    ):
        items.extend(parsed)
        report.errors.extend(errors)
        for finding in chunk:
            report.statuses[finding.finding_id] = status
    return items
