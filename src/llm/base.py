"""LLM backend abstraction layer with pluggable providers."""

import abc
import functools
import hashlib
import importlib.util
import json
import logging
import os
import time
from collections.abc import Callable
from typing import Any

from ..models.llm import LLMResponse

logger = logging.getLogger(__name__)

_MAX_RETRIES = 3
_BASE_DELAY = 1.0
_RETRYABLE_CODES = {429, 500, 502, 503}


def _is_retryable(exc: Exception) -> bool:
    status = getattr(exc, "status_code", None)
    if status is None:
        response = getattr(exc, "response", None)
        if response is not None:
            status = getattr(response, "status_code", None)
    return isinstance(status, int) and status in _RETRYABLE_CODES


def _retry_on_transient(func: Callable[..., Any]) -> Callable[..., Any]:
    @functools.wraps(func)
    def wrapper(*args: Any, **kwargs: Any) -> Any:
        last_exc: Exception | None = None
        for attempt in range(_MAX_RETRIES):
            try:
                return func(*args, **kwargs)
            except Exception as exc:
                if not _is_retryable(exc):
                    raise
                last_exc = exc
                delay = _BASE_DELAY * (2**attempt)
                logger.warning(
                    "Transient error (attempt %d/%d), retrying in %.1fs: %s",
                    attempt + 1,
                    _MAX_RETRIES,
                    delay,
                    exc,
                )
                time.sleep(delay)
        raise last_exc  # type: ignore[misc]

    return wrapper


class ResponseCache:
    """Simple in-memory LLM response cache with TTL eviction."""

    def __init__(self, max_entries: int = 200, ttl_seconds: float = 3600) -> None:
        self._cache: dict[str, tuple[float, LLMResponse]] = {}
        self._max = max_entries
        self._ttl = ttl_seconds

    @staticmethod
    def _key(prompt: str, system: str, model: str, temperature: float) -> str:
        raw = f"{system}|{prompt}|{model}|{temperature}"
        return hashlib.sha256(raw.encode()).hexdigest()

    @staticmethod
    def _key_messages(
        messages: list[dict[str, str]],
        system: str,
        model: str,
        temperature: float,
    ) -> str:
        raw = system + "|" + json.dumps(messages, sort_keys=True)
        raw += f"|{model}|{temperature}"
        return hashlib.sha256(raw.encode()).hexdigest()

    def get(self, key: str) -> LLMResponse | None:
        entry = self._cache.get(key)
        if entry is None:
            return None
        ts, response = entry
        if time.monotonic() - ts > self._ttl:
            del self._cache[key]
            return None
        return response

    def put(self, key: str, response: LLMResponse) -> None:
        # Evict oldest if at capacity
        if len(self._cache) >= self._max:
            oldest = min(self._cache, key=lambda k: self._cache[k][0])
            del self._cache[oldest]
        self._cache[key] = (time.monotonic(), response)


# Module-level shared cache
_response_cache = ResponseCache()


class BaseLLMBackend(abc.ABC):
    """Abstract interface for LLM providers."""

    name: str = "base"

    @abc.abstractmethod
    def complete(
        self,
        prompt: str,
        *,
        system: str = "",
        temperature: float = 0.2,
        max_tokens: int = 2048,
    ) -> LLMResponse:
        """Send a prompt to the LLM and return the response."""

    def complete_messages(
        self,
        messages: list[dict[str, str]],
        *,
        system: str = "",
        temperature: float = 0.2,
        max_tokens: int = 2048,
    ) -> LLMResponse:
        """Multi-turn completion with message history.

        Default implementation concatenates messages into a single prompt.
        Subclasses should override to use native multi-turn APIs.
        """
        parts = []
        for m in messages:
            label = "User" if m["role"] == "user" else "Assistant"
            parts.append(f"{label}: {m['content']}")
        combined = "\n\n".join(parts)
        return self.complete(
            combined,
            system=system,
            temperature=temperature,
            max_tokens=max_tokens,
        )

    def is_available(self) -> bool:
        return True


class OpenAIBackend(BaseLLMBackend):
    """OpenAI-compatible backend (works with OpenAI, Azure OpenAI, vLLM, etc.)."""

    name = "openai"

    def __init__(
        self,
        model: str = "gpt-4o",
        api_key: str | None = None,
        base_url: str | None = None,
    ) -> None:
        self.model = model
        self._api_key = api_key
        self._base_url = base_url
        self._client: Any = None

    def _get_client(self) -> Any:
        if self._client is None:
            try:
                import openai
            except ImportError as err:
                raise ImportError(
                    "The 'openai' package is required for OpenAIBackend. "
                    "Install it with: uv pip install openai"
                ) from err
            kwargs: dict[str, Any] = {}
            if self._api_key:
                kwargs["api_key"] = self._api_key
            if self._base_url:
                kwargs["base_url"] = self._base_url
            self._client = openai.OpenAI(**kwargs)
        return self._client

    def _call_openai(
        self,
        messages: list[dict[str, str]],
        temperature: float,
        max_tokens: int,
    ) -> LLMResponse:
        """Shared completion logic for single and multi-turn."""
        cache_key = _response_cache._key_messages(messages, "", self.model, temperature)
        cached = _response_cache.get(cache_key)
        if cached is not None:
            return cached

        client = self._get_client()
        call_kwargs: dict[str, Any] = {
            "model": self.model,
            "messages": messages,
            "temperature": temperature,
        }
        if self.model.startswith("o"):
            call_kwargs["max_completion_tokens"] = max_tokens
        else:
            call_kwargs["max_tokens"] = max_tokens

        response = client.chat.completions.create(**call_kwargs)

        choice = response.choices[0]
        usage = {}
        if response.usage:
            usage = {
                "prompt_tokens": response.usage.prompt_tokens,
                "completion_tokens": response.usage.completion_tokens,
                "total_tokens": response.usage.total_tokens,
            }

        result = LLMResponse(
            text=choice.message.content or "",
            model=response.model,
            usage=usage,
        )
        _response_cache.put(cache_key, result)
        return result

    @_retry_on_transient
    def complete(
        self,
        prompt: str,
        *,
        system: str = "",
        temperature: float = 0.2,
        max_tokens: int = 2048,
    ) -> LLMResponse:
        messages: list[dict[str, str]] = []
        if system:
            messages.append({"role": "system", "content": system})
        messages.append({"role": "user", "content": prompt})
        return self._call_openai(messages, temperature, max_tokens)

    @_retry_on_transient
    def complete_messages(
        self,
        messages: list[dict[str, str]],
        *,
        system: str = "",
        temperature: float = 0.2,
        max_tokens: int = 2048,
    ) -> LLMResponse:
        all_messages: list[dict[str, str]] = []
        if system:
            all_messages.append({"role": "system", "content": system})
        all_messages.extend(messages)
        return self._call_openai(all_messages, temperature, max_tokens)

    def is_available(self) -> bool:
        try:
            self._get_client()
            return True
        except Exception:
            return False


class AnthropicBackend(BaseLLMBackend):
    """Anthropic Claude backend."""

    name = "anthropic"

    def __init__(
        self,
        model: str = "claude-sonnet-4-6",
        api_key: str | None = None,
    ) -> None:
        self.model = model
        self._api_key = api_key
        self._client: Any = None

    def _get_client(self) -> Any:
        if self._client is None:
            try:
                import anthropic
            except ImportError as err:
                raise ImportError(
                    "The 'anthropic' package is required for AnthropicBackend. "
                    "Install it with: uv pip install anthropic"
                ) from err
            kwargs: dict[str, Any] = {}
            if self._api_key:
                kwargs["api_key"] = self._api_key
            self._client = anthropic.Anthropic(**kwargs)
        return self._client

    def _call_anthropic(
        self,
        messages: list[dict[str, str]],
        system: str,
        temperature: float,
        max_tokens: int,
    ) -> LLMResponse:
        """Shared completion logic for single and multi-turn."""
        cache_key = _response_cache._key_messages(
            messages, system, self.model, temperature
        )
        cached = _response_cache.get(cache_key)
        if cached is not None:
            return cached

        client = self._get_client()

        kwargs: dict[str, Any] = {
            "model": self.model,
            "max_tokens": max_tokens,
            "messages": messages,
        }
        if system:
            kwargs["system"] = system
        if temperature > 0:
            kwargs["temperature"] = temperature

        response = client.messages.create(**kwargs)

        text = ""
        for block in response.content:
            if hasattr(block, "text"):
                text += block.text

        usage = {
            "prompt_tokens": response.usage.input_tokens,
            "completion_tokens": response.usage.output_tokens,
            "total_tokens": (
                response.usage.input_tokens + response.usage.output_tokens
            ),
        }

        result = LLMResponse(
            text=text,
            model=response.model,
            usage=usage,
        )
        _response_cache.put(cache_key, result)
        return result

    @_retry_on_transient
    def complete(
        self,
        prompt: str,
        *,
        system: str = "",
        temperature: float = 0.2,
        max_tokens: int = 2048,
    ) -> LLMResponse:
        messages = [{"role": "user", "content": prompt}]
        return self._call_anthropic(messages, system, temperature, max_tokens)

    @_retry_on_transient
    def complete_messages(
        self,
        messages: list[dict[str, str]],
        *,
        system: str = "",
        temperature: float = 0.2,
        max_tokens: int = 2048,
    ) -> LLMResponse:
        return self._call_anthropic(messages, system, temperature, max_tokens)

    def is_available(self) -> bool:
        try:
            self._get_client()
            return True
        except Exception:
            return False


class OllamaBackend(BaseLLMBackend):
    """Local Ollama backend for air-gapped / offline environments."""

    name = "ollama"

    def __init__(
        self,
        model: str = "llama3.1",
        base_url: str = "http://localhost:11434",
    ) -> None:
        self.model = model
        self.base_url = base_url.rstrip("/")

    @_retry_on_transient
    def complete(
        self,
        prompt: str,
        *,
        system: str = "",
        temperature: float = 0.2,
        max_tokens: int = 2048,
    ) -> LLMResponse:
        import requests

        payload: dict[str, Any] = {
            "model": self.model,
            "prompt": prompt,
            "stream": False,
            "options": {
                "temperature": temperature,
                "num_predict": max_tokens,
            },
        }
        if system:
            payload["system"] = system

        resp = requests.post(
            f"{self.base_url}/api/generate",
            json=payload,
            timeout=120,
        )
        resp.raise_for_status()
        result = resp.json()

        return LLMResponse(
            text=result.get("response", ""),
            model=self.model,
            usage={
                "prompt_tokens": result.get("prompt_eval_count", 0),
                "completion_tokens": result.get("eval_count", 0),
                "total_tokens": (
                    result.get("prompt_eval_count", 0) + result.get("eval_count", 0)
                ),
            },
        )

    @_retry_on_transient
    def complete_messages(
        self,
        messages: list[dict[str, str]],
        *,
        system: str = "",
        temperature: float = 0.2,
        max_tokens: int = 2048,
    ) -> LLMResponse:
        import requests

        ollama_messages: list[dict[str, str]] = []
        if system:
            ollama_messages.append({"role": "system", "content": system})
        ollama_messages.extend(messages)

        payload: dict[str, Any] = {
            "model": self.model,
            "messages": ollama_messages,
            "stream": False,
            "options": {
                "temperature": temperature,
                "num_predict": max_tokens,
            },
        }

        resp = requests.post(
            f"{self.base_url}/api/chat",
            json=payload,
            timeout=120,
        )
        resp.raise_for_status()
        result = resp.json()

        msg = result.get("message", {})
        return LLMResponse(
            text=msg.get("content", ""),
            model=self.model,
            usage={
                "prompt_tokens": result.get("prompt_eval_count", 0),
                "completion_tokens": result.get("eval_count", 0),
                "total_tokens": (
                    result.get("prompt_eval_count", 0) + result.get("eval_count", 0)
                ),
            },
        )

    def is_available(self) -> bool:
        import requests

        try:
            resp = requests.get(f"{self.base_url}/api/tags", timeout=5)
            return resp.ok
        except Exception:
            return False


BACKEND_REGISTRY: dict[str, type[BaseLLMBackend]] = {
    "openai": OpenAIBackend,
    "anthropic": AnthropicBackend,
    "ollama": OllamaBackend,
}

# Maps backend name -> (required package, env var for API key)
_BACKEND_REQUIREMENTS: dict[str, tuple[str, str | None]] = {
    "anthropic": ("anthropic", "ANTHROPIC_API_KEY"),
    "openai": ("openai", "OPENAI_API_KEY"),
    "ollama": ("requests", None),  # no API key needed
}


def get_available_backends() -> list[dict[str, Any]]:
    """Return a list of backends with their availability status.

    Each entry has: name, available (bool), reason (str if unavailable).
    """
    results: list[dict[str, Any]] = []
    for name, (package, env_var) in _BACKEND_REQUIREMENTS.items():
        if importlib.util.find_spec(package) is None:
            results.append(
                {
                    "name": name,
                    "available": False,
                    "reason": f"Python package '{package}' is not installed",
                }
            )
            continue

        if env_var and not os.environ.get(env_var):
            results.append(
                {
                    "name": name,
                    "available": False,
                    "reason": f"Environment variable {env_var} is not set",
                }
            )
            continue

        results.append({"name": name, "available": True, "reason": ""})

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
    """Factory: instantiate an LLM backend by name."""
    cls = BACKEND_REGISTRY.get(backend_name)
    if cls is None:
        available = ", ".join(BACKEND_REGISTRY)
        raise ValueError(
            f"Unknown LLM backend {backend_name!r}. Available: {available}"
        )
    return cls(**kwargs)
