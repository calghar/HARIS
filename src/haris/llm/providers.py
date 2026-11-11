from typing import Any, override

from ..models.llm import LLMResponse
from .backend import LLMRequest, ProviderBackend
from .catalog import capabilities, default_model

SCHEMA_NAME = "haris_output"


class OpenAIBackend(ProviderBackend):
    """OpenAI-compatible backend (OpenAI, Azure OpenAI, vLLM, proxies)."""

    name = "openai"

    def __init__(
        self,
        model: str = "",
        api_key: str | None = None,
        base_url: str | None = None,
    ) -> None:
        self.model = model or default_model(self.name)
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
            kwargs: dict[str, Any] = {
                "timeout": self._cfg.runtime.timeout_s,
                "max_retries": 0,
            }
            if self._api_key:
                kwargs["api_key"] = self._api_key
            if self._base_url:
                kwargs["base_url"] = self._base_url
            self._client = openai.OpenAI(**kwargs)
        return self._client

    @override
    def _send(self, request: LLMRequest) -> LLMResponse:
        caps = capabilities(self.name, self.model, self._cfg)
        messages = list(request.messages)
        if request.system:
            messages.insert(0, {"role": "system", "content": request.system})
        kwargs: dict[str, Any] = {
            "model": self.model,
            "messages": messages,
            caps.token_param: request.max_tokens,
        }
        if caps.temperature:
            kwargs["temperature"] = request.temperature
        if request.response_schema is not None:
            if caps.json_schema:
                kwargs["response_format"] = {
                    "type": "json_schema",
                    "json_schema": {
                        "name": SCHEMA_NAME,
                        "schema": request.response_schema,
                        "strict": False,
                    },
                }
            elif caps.json_object:
                kwargs["response_format"] = {"type": "json_object"}

        response = self._get_client().chat.completions.create(**kwargs)
        usage = {}
        if response.usage:
            usage = {
                "prompt_tokens": response.usage.prompt_tokens,
                "completion_tokens": response.usage.completion_tokens,
                "total_tokens": response.usage.total_tokens,
            }
        return LLMResponse(
            text=response.choices[0].message.content or "",
            model=response.model,
            usage=usage,
        )

    @override
    def is_available(self) -> bool:
        try:
            self._get_client()
            return True
        except Exception:
            return False


class AnthropicBackend(ProviderBackend):
    """Anthropic Claude backend."""

    name = "anthropic"

    def __init__(self, model: str = "", api_key: str | None = None) -> None:
        self.model = model or default_model(self.name)
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
            kwargs: dict[str, Any] = {
                "timeout": self._cfg.runtime.timeout_s,
                "max_retries": 0,
            }
            if self._api_key:
                kwargs["api_key"] = self._api_key
            self._client = anthropic.Anthropic(**kwargs)
        return self._client

    @override
    def _send(self, request: LLMRequest) -> LLMResponse:
        caps = capabilities(self.name, self.model, self._cfg)
        kwargs: dict[str, Any] = {
            "model": self.model,
            caps.token_param: request.max_tokens,
            "messages": request.messages,
        }
        if request.system:
            kwargs["system"] = request.system
        if caps.temperature:
            kwargs["temperature"] = request.temperature
        if request.response_schema is not None and caps.json_schema:
            kwargs["output_config"] = {
                "format": {"type": "json_schema", "schema": request.response_schema}
            }

        response = self._get_client().messages.create(**kwargs)
        text = "".join(b.text for b in response.content if hasattr(b, "text"))
        used = response.usage
        return LLMResponse(
            text=text,
            model=response.model,
            usage={
                "prompt_tokens": used.input_tokens,
                "completion_tokens": used.output_tokens,
                "total_tokens": used.input_tokens + used.output_tokens,
            },
        )

    @override
    def is_available(self) -> bool:
        try:
            self._get_client()
            return True
        except Exception:
            return False


class OllamaBackend(ProviderBackend):
    """Local Ollama backend for air-gapped / offline environments."""

    name = "ollama"

    def __init__(
        self,
        model: str = "",
        base_url: str = "http://localhost:11434",
    ) -> None:
        self.model = model or default_model(self.name)
        self.base_url = base_url.rstrip("/")

    @override
    def _send(self, request: LLMRequest) -> LLMResponse:
        import requests

        caps = capabilities(self.name, self.model, self._cfg)
        messages = list(request.messages)
        if request.system:
            messages.insert(0, {"role": "system", "content": request.system})
        options: dict[str, Any] = {caps.token_param: request.max_tokens}
        if caps.temperature:
            options["temperature"] = request.temperature
        payload: dict[str, Any] = {
            "model": self.model,
            "messages": messages,
            "stream": False,
            "options": options,
        }
        if request.response_schema is not None:
            payload["format"] = request.response_schema if caps.json_schema else "json"

        resp = requests.post(
            f"{self.base_url}/api/chat",
            json=payload,
            timeout=self._cfg.runtime.timeout_s,
        )
        resp.raise_for_status()
        result = resp.json()
        prompt_tokens = result.get("prompt_eval_count", 0)
        completion_tokens = result.get("eval_count", 0)
        return LLMResponse(
            text=result.get("message", {}).get("content", ""),
            model=self.model,
            usage={
                "prompt_tokens": prompt_tokens,
                "completion_tokens": completion_tokens,
                "total_tokens": prompt_tokens + completion_tokens,
            },
        )

    @override
    def is_available(self) -> bool:
        import requests

        try:
            return requests.get(f"{self.base_url}/api/tags", timeout=5).ok
        except Exception:
            return False
