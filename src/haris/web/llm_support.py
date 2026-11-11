import logging
from collections.abc import Iterator
from contextlib import contextmanager

from fastapi import HTTPException

from ..llm.base import create_backend, get_default_backend_name
from ..llm.budget import BudgetExceededError
from ..llm.qa import ReportQA
from ..models import LLMResponse
from .schemas.llm import Answer

logger = logging.getLogger(__name__)


@contextmanager
def llm_errors(what: str) -> Iterator[None]:
    """Map LLM failures to generic HTTP errors; details go to the log only."""
    try:
        yield
    except HTTPException:
        raise
    except BudgetExceededError as exc:
        logger.warning("LLM budget exceeded during %s: %s", what, exc)
        raise HTTPException(status_code=429, detail="LLM budget exceeded") from exc
    except ImportError as exc:
        logger.warning("LLM backend unavailable during %s: %s", what, exc)
        raise HTTPException(
            status_code=501, detail="LLM backend not available"
        ) from exc
    except Exception as exc:
        logger.exception("LLM request failed during %s", what)
        raise HTTPException(status_code=500, detail="LLM request failed") from exc


def make_qa(backend_name: str | None = None) -> ReportQA:
    return ReportQA(backend=create_backend(backend_name or get_default_backend_name()))


def answer(response: LLMResponse) -> Answer:
    return Answer(
        answer=response.text, model=response.model, tokens=response.token_count
    )
