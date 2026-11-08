import abc
import collections
import functools
import hashlib
import json
import logging
import threading
import time
from collections.abc import Callable
from typing import Any

from pydantic import BaseModel

from ..models.llm import LLMResponse
from .budget import LLMBudget
from .redaction import Redactor
from .retry import Retrier, status_of
from .settings import LLMSettings, load_settings

logger = logging.getLogger(__name__)

BAD_REQUEST = 400


class ResponseCache:
    """LRU in-memory LLM response cache with TTL eviction."""

    def __init__(self, max_entries: int = 200, ttl_seconds: float = 3600) -> None:
        self._cache: collections.OrderedDict[str, tuple[float, LLMResponse]] = (
            collections.OrderedDict()
        )
        self._max = max_entries
        self._ttl = ttl_seconds
        self._lock = threading.Lock()

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
        schema: dict[str, Any] | None = None,
    ) -> str:
        raw = system + "|" + json.dumps(messages, sort_keys=True)
        raw += f"|{model}|{temperature}|{json.dumps(schema, sort_keys=True)}"
        return hashlib.sha256(raw.encode()).hexdigest()

    def get(self, key: str) -> LLMResponse | None:
        with self._lock:
            entry = self._cache.get(key)
            if entry is None:
                return None
            ts, response = entry
            if time.monotonic() - ts > self._ttl:
                del self._cache[key]
                return None
            self._cache.move_to_end(key)
            return response

    def put(self, key: str, response: LLMResponse) -> None:
        with self._lock:
            if key in self._cache:
                self._cache.move_to_end(key)
            elif len(self._cache) >= self._max:
                self._cache.popitem(last=False)
            self._cache[key] = (time.monotonic(), response)

    def clear(self) -> None:
        """Drop all cached responses."""
        with self._lock:
            self._cache.clear()


_response_cache = ResponseCache()


class BaseLLMBackend(abc.ABC):
    """Abstract interface for LLM providers."""

    name: str = "base"
    model: str = ""
    budget: LLMBudget | None = None

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
        """Multi-turn completion; the default flattens the history into one prompt."""
        parts = []
        for m in messages:
            label = "User" if m["role"] == "user" else "Assistant"
            parts.append(f"{label}: {m['content']}")
        return self.complete(
            "\n\n".join(parts),
            system=system,
            temperature=temperature,
            max_tokens=max_tokens,
        )

    def is_available(self) -> bool:
        return True


class LLMRequest(BaseModel):
    messages: list[dict[str, str]]
    system: str = ""
    temperature: float = 0.2
    max_tokens: int = 2048
    response_schema: dict[str, Any] | None = None


class ProviderBackend(BaseLLMBackend):
    """Shared call path: redact, cache, reserve budget, gate, retry, settle."""

    cache: ResponseCache | None = _response_cache
    settings: LLMSettings | None = None
    sleep: Callable[[float], None] = time.sleep

    @abc.abstractmethod
    def _send(self, request: LLMRequest) -> LLMResponse:
        """One provider call on an already redacted request."""

    @functools.cached_property
    def _cfg(self) -> LLMSettings:
        return self.settings or load_settings()

    @functools.cached_property
    def _redactor(self) -> Redactor:
        return Redactor(self._cfg)

    @functools.cached_property
    def _gate(self) -> threading.BoundedSemaphore:
        return threading.BoundedSemaphore(self._cfg.runtime.max_concurrency)

    @functools.cached_property
    def _retrier(self) -> Retrier:
        return Retrier(self._cfg.runtime, sleep=self.sleep)

    def complete(
        self,
        prompt: str,
        *,
        system: str = "",
        temperature: float = 0.2,
        max_tokens: int = 2048,
        response_schema: dict[str, Any] | None = None,
    ) -> LLMResponse:
        return self.complete_messages(
            [{"role": "user", "content": prompt}],
            system=system,
            temperature=temperature,
            max_tokens=max_tokens,
            response_schema=response_schema,
        )

    def complete_messages(
        self,
        messages: list[dict[str, str]],
        *,
        system: str = "",
        temperature: float = 0.2,
        max_tokens: int = 2048,
        response_schema: dict[str, Any] | None = None,
    ) -> LLMResponse:
        redact = self._redactor.redact
        safe = [{**m, "content": redact(m["content"])} for m in messages]
        system = redact(system)
        key = ResponseCache._key_messages(
            safe, system, self.model, temperature, response_schema
        )
        if self.cache is not None and (hit := self.cache.get(key)) is not None:
            return hit

        chars = len(system) + sum(len(m["content"]) for m in safe)
        prompt_tokens = chars // self._cfg.runtime.chars_per_token + 1
        reservation = (
            self.budget.reserve(prompt_tokens, max_tokens, self.model)
            if self.budget
            else None
        )
        request = LLMRequest(
            messages=safe,
            system=system,
            temperature=temperature,
            max_tokens=reservation.max_tokens if reservation else max_tokens,
            response_schema=response_schema,
        )
        try:
            with self._gate:
                response = self._retrier.call(lambda: self._send_structured(request))
        except BaseException:
            if self.budget and reservation:
                self.budget.release(reservation)
            raise
        if not response.usage.get("total_tokens"):
            out = len(response.text) // self._cfg.runtime.chars_per_token + 1
            response = response.model_copy(
                update={
                    "usage": {
                        "prompt_tokens": prompt_tokens,
                        "completion_tokens": out,
                        "total_tokens": prompt_tokens + out,
                    }
                }
            )
        if self.budget and reservation:
            self.budget.settle(reservation, response.usage)
        if self.cache is not None:
            self.cache.put(key, response)
        return response

    def _send_structured(self, request: LLMRequest) -> LLMResponse:
        try:
            return self._send(request)
        except Exception as exc:
            if request.response_schema is None or status_of(exc) != BAD_REQUEST:
                raise
            logger.warning("%s rejected structured output; retrying plain", self.name)
            return self._send(request.model_copy(update={"response_schema": None}))
