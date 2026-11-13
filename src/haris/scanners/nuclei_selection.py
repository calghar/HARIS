import logging
import re
from collections.abc import Callable, Sequence
from typing import Literal

from pydantic import BaseModel, ConfigDict

from ..llm.backend import BaseLLMBackend
from ..llm.budget import BudgetExceededError
from ..llm.redaction import DATA_CLAUSE, fence, new_nonce, redact
from ..llm.structured import call_structured
from ..models.scan_context import ScanContext
from ..net.redact import redact_headers
from .nuclei_templates import ANSI_ESCAPE
from .process import ToolTimeoutError

logger = logging.getLogger(__name__)

TAG_LIST_COMMAND = ["nuclei", "-tgl"]
# `<tag> (<template count>)`; tags outside this charset cannot sit in a comma list.
TAG_LINE = re.compile(r"([a-z0-9][a-z0-9._+-]*) \((\d+)\)")
TEMPERATURE = 0.0
MAX_OUTPUT_TOKENS = 400
NOTE_PREFIX = "template selection:"

DISABLED = "selector disabled"
NO_ALLOWLIST = "allowlist unavailable"
NO_INPUT = "no technologies recorded"
NO_BUDGET = "no budget"
CALL_FAILED = "call failed"
INVALID = "invalid answer"
OUTSIDE = "tag outside allowlist"
TOO_MANY = "too many tags"


class SelectionResult(BaseModel):
    model_config = ConfigDict(frozen=True)

    tags: tuple[str, ...] = ()
    source: Literal["llm", "deterministic"] = "deterministic"
    model: str = ""
    reason: str = ""


class TagsOut(BaseModel):
    model_config = ConfigDict(extra="forbid")

    tags: list[str]


def system_prompt(max_tags: int) -> str:
    return (
        f"{DATA_CLAUSE}\n"
        "You choose nuclei template tags for a web scan. Pick up to "
        f"{max_tags} tags from the allowed tags that fit the technologies, server "
        "headers and open ports. Use only allowed tags, copied exactly. Reply with "
        'one JSON object {"tags": [<tag>, ...]}; an empty list is a valid answer.'
    )


def build_prompt(context: ScanContext, allowed: frozenset[str]) -> str | None:
    """Fenced recon facts plus the allowlist; None when there is nothing to send."""
    headers = {
        name: value
        for name, value in context.server_headers.items()
        if redact_headers({name: value})[name] == value
    }
    sections = [
        ("Technologies", "\n".join(context.detected_technologies)),
        ("Server headers", "\n".join(f"{k}: {v}" for k, v in headers.items())),
        ("Open ports", "\n".join(context.open_ports)),
    ]
    sections = [(label, redact(text)) for label, text in sections if text]
    if not sections:
        return None
    nonce = new_nonce()
    while any(nonce in text for _, text in sections):
        nonce = new_nonce()
    parts = [f"Allowed tags: {','.join(sorted(allowed))}"]
    for label, text in sections:
        parts += [f"{label}:", fence(text, nonce)]
    return "\n".join(parts)


def judge_answer(
    answer: TagsOut, allowed: frozenset[str], max_tags: int, model: str
) -> SelectionResult:
    """Accept the whole answer or none of it."""
    tags = tuple(dict.fromkeys(t.strip().lower() for t in answer.tags))
    if any(t not in allowed for t in tags):
        return SelectionResult(model=model, reason=OUTSIDE)
    if len(tags) > max_tags:
        return SelectionResult(model=model, reason=TOO_MANY)
    return SelectionResult(tags=tags, source="llm", model=model)


def read_allowlist(
    run_command: Callable[[list[str]], tuple[int, str, str]],
    deny_tags: Sequence[str],
    min_templates: int,
    max_templates: int,
) -> frozenset[str] | None:
    """Tags carried by min to max templates in this environment, minus denied."""
    try:
        returncode, stdout, stderr = run_command(list(TAG_LIST_COMMAND))
    except (OSError, ToolTimeoutError):
        logger.warning("nuclei tag list could not run", exc_info=True)
        return None
    if returncode != 0:
        logger.warning("nuclei tag list exited %d: %s", returncode, stderr.strip())
        return None
    denied = {t.strip().lower() for t in deny_tags}
    tags = {
        match.group(1)
        for line in ANSI_ESCAPE.sub("", stdout).splitlines()
        if (match := TAG_LINE.fullmatch(line.strip().lower()))
        and min_templates <= int(match.group(2)) <= max_templates
    } - denied
    return frozenset(tags) or None


def select_tags(
    context: ScanContext,
    backend: BaseLLMBackend | None,
    allowed: frozenset[str] | None,
    *,
    max_tags: int,
) -> SelectionResult:
    """One LLM call choosing extra nuclei tags; any failure states its reason."""
    if backend is None:
        return SelectionResult(reason=DISABLED)
    if not allowed:
        return SelectionResult(reason=NO_ALLOWLIST)
    prompt = build_prompt(context, allowed)
    if prompt is None:
        return SelectionResult(reason=NO_INPUT)
    model = backend.model
    try:
        result = call_structured(
            backend,
            prompt,
            system=system_prompt(max_tags),
            model=TagsOut,
            many=False,
            temperature=TEMPERATURE,
            max_tokens=MAX_OUTPUT_TOKENS,
        )
    except BudgetExceededError as exc:
        logger.info("nuclei tag selector skipped: %s", exc)
        return SelectionResult(model=model, reason=NO_BUDGET)
    except Exception:
        logger.warning("nuclei tag selector call failed", exc_info=True)
        return SelectionResult(model=model, reason=CALL_FAILED)
    if not result.items:
        logger.info("nuclei tag selector answer invalid: %s", result.errors)
        return SelectionResult(model=model, reason=INVALID)
    selection = judge_answer(result.items[0], allowed, max_tags, model)
    if selection.reason:
        logger.info("nuclei tag selector answer discarded: %s", selection.reason)
    return selection


def selection_note(result: SelectionResult) -> str:
    if result.source == "llm":
        return f"{NOTE_PREFIX} llm tags {', '.join(result.tags) or 'none'}"
    return f"{NOTE_PREFIX} deterministic ({result.reason})"
