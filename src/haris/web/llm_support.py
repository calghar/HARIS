import logging
import os
from collections.abc import Iterator
from contextlib import contextmanager
from urllib.parse import urlsplit

from fastapi import HTTPException

from ..config.loader import load_config
from ..llm.base import BACKEND_REGISTRY, create_backend, create_backend_from_config
from ..llm.budget import BudgetExceededError
from ..llm.litellm_backend import LLMConfigError, scrub
from ..llm.qa import ReportQA
from ..models import LLMResponse
from ..models.config import DEFAULT_API_KEY_ENV, LLMConfig
from .schemas.llm import Answer

logger = logging.getLogger(__name__)


def llm_config() -> LLMConfig:
    return load_config().llm


def endpoint_display(api_base: str) -> str:
    """scheme://host[:port] of the endpoint; userinfo, path and query are dropped."""
    try:
        parts = urlsplit(api_base)
        host, port = parts.hostname, parts.port
    except ValueError:
        return ""
    if not (parts.scheme and host):
        return ""
    shown = f"[{host}]" if ":" in host else host
    return f"{parts.scheme}://{shown}" + (f":{port}" if port else "")


def _api_key() -> str | None:
    try:
        env_name = llm_config().api_key_env
    except Exception:
        env_name = DEFAULT_API_KEY_ENV
    return os.environ.get(env_name) or None


@contextmanager
def llm_errors(what: str) -> Iterator[None]:
    """Map LLM failures to generic HTTP errors; scrubbed details go to the log only."""
    try:
        yield
    except HTTPException:
        raise
    except LLMConfigError as exc:
        key = _api_key()
        logger.warning(
            "LLM configuration rejected during %s: %s", what, scrub(str(exc), key)
        )
        raise HTTPException(status_code=400, detail=scrub(str(exc), key)) from exc
    except BudgetExceededError as exc:
        logger.warning(
            "LLM budget exceeded during %s: %s", what, scrub(str(exc), _api_key())
        )
        raise HTTPException(status_code=429, detail="LLM budget exceeded") from exc
    except ImportError as exc:
        logger.warning(
            "LLM backend unavailable during %s: %s", what, scrub(str(exc), _api_key())
        )
        raise HTTPException(
            status_code=501, detail="LLM backend not available"
        ) from exc
    except Exception as exc:
        logger.error(
            "LLM request failed during %s: %s", what, scrub(str(exc), _api_key())
        )
        raise HTTPException(status_code=500, detail="LLM request failed") from exc


def make_qa(backend_name: str | None = None) -> ReportQA:
    return ReportQA(backend=create_backend_from_config(llm_config(), backend_name))


def reject_legacy_backend(backend_name: str | None) -> None:
    """400 for a backend name other than litellm; blank means the default."""
    if backend_name and backend_name not in BACKEND_REGISTRY:
        with llm_errors("backend selection"):
            create_backend(backend_name)


def check_scan_llm(backend_name: str | None, enrich: bool) -> None:
    """400 at submission when the scan needs an LLM backend that cannot be built."""
    cfg = llm_config()
    if enrich or cfg.enrichment_enabled:
        with llm_errors("scan submission"):
            create_backend_from_config(cfg, backend_name)
    else:
        reject_legacy_backend(backend_name)


def answer(response: LLMResponse) -> Answer:
    return Answer(
        answer=response.text, model=response.model, tokens=response.token_count
    )
