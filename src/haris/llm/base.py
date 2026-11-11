import importlib.util
import os
from typing import Any

from ..models.llm import LLMResponse
from .backend import (
    BaseLLMBackend,
    LLMRequest,
    ProviderBackend,
    ResponseCache,
)
from .catalog import API_KEY_ENV, resolve_model
from .providers import AnthropicBackend, OllamaBackend, OpenAIBackend
from .settings import load_settings

__all__ = [
    "BACKEND_REGISTRY",
    "AnthropicBackend",
    "BaseLLMBackend",
    "LLMRequest",
    "LLMResponse",
    "OllamaBackend",
    "OpenAIBackend",
    "ProviderBackend",
    "ResponseCache",
    "create_backend",
    "get_available_backends",
    "get_default_backend_name",
]

BACKEND_REGISTRY: dict[str, type[BaseLLMBackend]] = {
    "openai": OpenAIBackend,
    "anthropic": AnthropicBackend,
    "ollama": OllamaBackend,
}

# Maps backend name -> (required package, env var for API key)
_BACKEND_REQUIREMENTS: dict[str, tuple[str, str | None]] = {
    "anthropic": ("anthropic", API_KEY_ENV["anthropic"]),
    "openai": ("openai", API_KEY_ENV["openai"]),
    "ollama": ("requests", None),  # no API key needed
}


def get_available_backends() -> list[dict[str, Any]]:
    """Return a list of backends with their availability status.

    Each entry has: name, available (bool), reason (str if unavailable).
    """
    results: list[dict[str, Any]] = []
    for name, (package, env_var) in _BACKEND_REQUIREMENTS.items():
        if importlib.util.find_spec(package) is None:
            reason = f"Python package '{package}' is not installed"
        elif env_var and not os.environ.get(env_var):
            reason = f"Environment variable {env_var} is not set"
        else:
            results.append({"name": name, "available": True, "reason": ""})
            continue
        results.append({"name": name, "available": False, "reason": reason})
    return results


def get_default_backend_name() -> str:
    """Return the name of the first available backend, or 'anthropic' as fallback."""
    for entry in get_available_backends():
        if entry["available"]:
            return str(entry["name"])
    return "anthropic"


def create_backend(
    backend_name: str = "openai",
    **kwargs: Any,
) -> BaseLLMBackend:
    """Instantiate a backend; an unset model comes from config."""
    cls = BACKEND_REGISTRY.get(backend_name)
    if cls is None:
        available = ", ".join(BACKEND_REGISTRY)
        raise ValueError(
            f"Unknown LLM backend {backend_name!r}. Available: {available}"
        )
    if not kwargs.get("model") and backend_name in load_settings().providers:
        kwargs["model"] = resolve_model(
            backend_name,
            api_key=kwargs.get("api_key"),
            base_url=kwargs.get("base_url"),
        )
    return cls(**kwargs)
