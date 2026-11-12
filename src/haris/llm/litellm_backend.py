import functools
import importlib.util
import logging
import os
from typing import Any, override

from ..models.config import DEFAULT_API_KEY_ENV
from ..models.llm import LLMResponse
from .backend import LLMRequest, ProviderBackend
from .retry import Retrier

logger = logging.getLogger(__name__)

SCHEMA_NAME = "haris_output"
REDACTED = "[REDACTED]"


class LLMConfigError(ValueError):
    """The LLM backend name or model string is not usable."""


def validate_model(model: str) -> str:
    """Return the model unchanged when it has the form <route>/<id>."""
    route, _, ident = model.partition("/")
    if route.strip() and ident.strip():
        return model
    shown = repr(model) if model.strip() else "blank"
    raise LLMConfigError(
        f"llm.model is {shown}, not a LiteLLM model string <route>/<id>. "
        "Set llm.model, for example bedrock/<inference profile id>, "
        "openai/<gateway alias> or ollama_chat/<tag>."
    )


def scrub(text: str, api_key: str | None) -> str:
    return text.replace(api_key, REDACTED) if api_key else text


def scrub_exception(exc: BaseException, api_key: str) -> None:
    """Redact the key in place from args, text attributes and the cause chain."""
    seen: set[int] = set()
    link: BaseException | None = exc
    while link is not None and id(link) not in seen:
        seen.add(id(link))
        link.args = tuple(
            scrub(a, api_key) if isinstance(a, str) else a for a in link.args
        )
        for name, value in vars(link).items():
            if isinstance(value, str):
                setattr(link, name, scrub(value, api_key))
        link = link.__cause__ or link.__context__


def table_cost(model: str, prompt_tokens: int, output_tokens: int) -> float | None:
    """USD from LiteLLM's price table; None when unpriced or LiteLLM is absent."""
    try:
        import litellm

        litellm.suppress_debug_info = True
        prompt_usd, output_usd = litellm.cost_per_token(
            model=model, prompt_tokens=prompt_tokens, completion_tokens=output_tokens
        )
        return float(prompt_usd + output_usd)
    except Exception:
        logger.debug("No LiteLLM price for %s", model)
        return None


class LiteLLMBackend(ProviderBackend):
    """Every model call: gateway, Bedrock, Ollama and other LiteLLM routes."""

    name = "litellm"

    def __init__(
        self,
        model: str = "",
        api_base: str = "",
        api_key_env: str = DEFAULT_API_KEY_ENV,
    ) -> None:
        self.model = model
        self.api_base = api_base
        self.api_key_env = api_key_env

    def _api_key(self) -> str | None:
        return os.environ.get(self.api_key_env) or None

    @functools.cached_property
    @override
    def _retrier(self) -> Retrier:
        return Retrier(
            self._cfg.runtime,
            sleep=self.sleep,
            scrub=lambda text: scrub(text, self._api_key()),
        )

    @override
    def _send(self, request: LLMRequest) -> LLMResponse:
        import litellm

        messages = list(request.messages)
        if request.system:
            messages.insert(0, {"role": "system", "content": request.system})
        kwargs: dict[str, Any] = {
            "model": self.model,
            "messages": messages,
            "max_tokens": request.max_tokens,
            "temperature": request.temperature,
            "num_retries": 0,
            "timeout": self._cfg.runtime.timeout_s,
            "drop_params": True,
        }
        if request.response_schema is not None:
            kwargs["response_format"] = {
                "type": "json_schema",
                "json_schema": {
                    "name": SCHEMA_NAME,
                    "schema": request.response_schema,
                    "strict": False,
                },
            }
        if self.api_base:
            kwargs["api_base"] = self.api_base
        api_key = self._api_key()
        if api_key:
            kwargs["api_key"] = api_key

        try:
            response: Any = litellm.completion(**kwargs)
        except Exception as exc:
            if api_key:
                scrub_exception(exc, api_key)
            raise
        usage = {}
        if response.usage:
            usage = {
                "prompt_tokens": response.usage.prompt_tokens,
                "completion_tokens": response.usage.completion_tokens,
                "total_tokens": response.usage.total_tokens,
            }
        return LLMResponse(
            text=response.choices[0].message.content or "",
            model=response.model or self.model,
            usage=usage,
        )

    @override
    def is_available(self) -> bool:
        if importlib.util.find_spec("litellm") is None:
            return False
        try:
            validate_model(self.model)
        except LLMConfigError:
            return False
        return True
