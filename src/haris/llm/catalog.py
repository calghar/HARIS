import hashlib
import logging
import os
from collections.abc import Callable
from typing import Any

from .settings import Capability, LLMSettings, load_settings

logger = logging.getLogger(__name__)

API_KEY_ENV = {"anthropic": "ANTHROPIC_API_KEY", "openai": "OPENAI_API_KEY"}

ModelLister = Callable[[], list[str]]

_listed: dict[tuple[str, str, str], list[str]] = {}


def default_model(provider: str, settings: LLMSettings | None = None) -> str:
    models = (settings or load_settings()).providers.get(provider)
    if models is None:
        raise ValueError(f"No models configured for provider {provider!r}")
    return models.default


def capabilities(
    provider: str, model: str, settings: LLMSettings | None = None
) -> Capability:
    return (settings or load_settings()).capability(provider, model)


def _list_via_sdk(provider: str, api_key: str, base_url: str | None) -> list[str]:
    timeout = load_settings().runtime.timeout_s
    client: Any
    if provider == "anthropic":
        import anthropic

        client = anthropic.Anthropic(api_key=api_key, timeout=timeout, max_retries=0)
    else:
        import openai

        kwargs: dict[str, Any] = {"api_key": api_key, "timeout": timeout}
        if base_url:
            kwargs["base_url"] = base_url
        client = openai.OpenAI(max_retries=0, **kwargs)
    return [str(m.id) for m in client.models.list()]


def list_provider_models(
    provider: str, api_key: str, base_url: str | None = None
) -> list[str]:
    key = (provider, base_url or "", hashlib.sha256(api_key.encode()).hexdigest())
    if key not in _listed:
        _listed[key] = _list_via_sdk(provider, api_key, base_url)
    return _listed[key]


def resolve_model(
    provider: str,
    *,
    requested: str = "",
    api_key: str | None = None,
    base_url: str | None = None,
    lister: ModelLister | None = None,
    settings: LLMSettings | None = None,
) -> str:
    """Explicit model, else first configured model the provider lists, else default."""
    if requested:
        return requested
    cfg = settings or load_settings()
    models = cfg.providers.get(provider)
    if models is None:
        raise ValueError(f"No models configured for provider {provider!r}")
    key = api_key or os.environ.get(API_KEY_ENV.get(provider, ""), "")
    if lister is None and (not key or provider not in API_KEY_ENV):
        return models.default
    try:
        available = set(
            lister() if lister else list_provider_models(provider, key, base_url)
        )
    except Exception:
        logger.warning("Model list for %s unavailable; using default", provider)
        return models.default
    for candidate in (models.default, *models.fallbacks):
        if candidate in available:
            return candidate
    logger.warning("No configured %s model is listed; using default", provider)
    return models.default
