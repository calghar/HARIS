import importlib.util
from typing import Any

from ..models.config import LLMConfig
from ..models.llm import LLMResponse
from .backend import (
    BaseLLMBackend,
    LLMRequest,
    ProviderBackend,
    ResponseCache,
)
from .litellm_backend import LiteLLMBackend, LLMConfigError, validate_model

__all__ = [
    "BACKEND_REGISTRY",
    "BaseLLMBackend",
    "LLMRequest",
    "LLMResponse",
    "LiteLLMBackend",
    "ProviderBackend",
    "ResponseCache",
    "create_backend",
    "create_backend_from_config",
    "get_available_backends",
    "get_default_backend_name",
]

BACKEND_REGISTRY: dict[str, type[BaseLLMBackend]] = {"litellm": LiteLLMBackend}

DEFAULT_BACKEND = "litellm"


def get_available_backends(model: str = "") -> list[dict[str, Any]]:
    """Each entry has: name, available (bool), reason (str if unavailable)."""
    reason = ""
    if importlib.util.find_spec("litellm") is None:
        reason = "Python package 'litellm' is not installed"
    else:
        try:
            validate_model(model)
        except LLMConfigError as exc:
            reason = str(exc)
    return [{"name": DEFAULT_BACKEND, "available": not reason, "reason": reason}]


def get_default_backend_name() -> str:
    return DEFAULT_BACKEND


def create_backend(
    backend_name: str = DEFAULT_BACKEND,
    **kwargs: Any,
) -> BaseLLMBackend:
    """Instantiate a backend; raises LLMConfigError for a legacy name or bad model."""
    cls = BACKEND_REGISTRY.get(backend_name)
    if cls is None:
        raise LLMConfigError(
            f"LLM backend {backend_name!r} no longer exists. Set the backend to "
            f"{DEFAULT_BACKEND!r} and put the provider route in llm.model "
            "(for example bedrock/<inference profile id>)."
        )
    validate_model(kwargs.get("model", ""))
    return cls(**kwargs)


def create_backend_from_config(
    llm: LLMConfig, backend_name: str | None = None, model: str = ""
) -> BaseLLMBackend:
    """Backend for `llm`; `backend_name` and `model` override the config values."""
    return create_backend(
        backend_name or llm.backend,
        model=model or llm.model,
        api_base=llm.api_base,
        api_key_env=llm.api_key_env,
    )
