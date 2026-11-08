import typing
from types import SimpleNamespace

import pytest

from haris.llm import catalog
from haris.llm.base import create_backend
from haris.llm.catalog import capabilities, resolve_model
from haris.llm.providers import AnthropicBackend, OllamaBackend, OpenAIBackend
from haris.llm.settings import load_settings


class _Recorder:
    def __init__(self, response):
        self.kwargs: dict = {}
        self._response = response

    def create(self, **kwargs):
        self.kwargs = kwargs
        return self._response


def _openai_backend(model: str) -> tuple[OpenAIBackend, _Recorder]:
    response = SimpleNamespace(
        choices=[SimpleNamespace(message=SimpleNamespace(content="{}"))],
        model=model,
        usage=SimpleNamespace(prompt_tokens=3, completion_tokens=2, total_tokens=5),
    )
    recorder = _Recorder(response)
    backend = OpenAIBackend(model=model)
    backend.cache = None
    backend._client = SimpleNamespace(chat=SimpleNamespace(completions=recorder))
    return backend, recorder


class TestCapabilityTable:
    @pytest.mark.parametrize(
        "provider,model,token_param,temperature",
        [
            ("openai", "o3", "max_completion_tokens", False),
            ("openai", "o4-mini", "max_completion_tokens", False),
            ("openai", "gpt-5.5", "max_completion_tokens", False),
            ("openai", "gpt-4.1", "max_tokens", True),
            ("openai", "gpt-4o-mini", "max_tokens", True),
            ("openai", "omni-local-7b", "max_tokens", True),
            ("anthropic", "claude-sonnet-5-5", "max_tokens", False),
            ("ollama", "llama3.1", "num_predict", True),
        ],
    )
    def test_lookup(self, provider, model, token_param, temperature):
        caps = capabilities(provider, model)
        assert (caps.token_param, caps.temperature) == (token_param, temperature)

    def test_openai_token_parameter_follows_capabilities_not_the_name_prefix(self):
        """Regression: a leading 'o' no longer selects max_completion_tokens."""
        for model, expected in [
            ("o3", "max_completion_tokens"),
            ("gpt-5.5", "max_completion_tokens"),
            ("omni-local-7b", "max_tokens"),
        ]:
            backend, recorder = _openai_backend(model)
            backend.complete("hi", max_tokens=123)
            assert recorder.kwargs[expected] == 123
            other = {"max_tokens", "max_completion_tokens"} - {expected}
            assert other.isdisjoint(recorder.kwargs)

    def test_temperature_is_sent_only_where_supported(self):
        for model, sent in [("gpt-4.1", True), ("o3", False)]:
            backend, recorder = _openai_backend(model)
            backend.complete("hi", temperature=0.4)
            assert ("temperature" in recorder.kwargs) is sent

    def test_openai_json_schema_request_uses_response_format(self):
        backend, recorder = _openai_backend("gpt-5.5")
        backend.complete("hi", response_schema={"type": "object"})
        assert recorder.kwargs["response_format"]["type"] == "json_schema"
        backend, recorder = _openai_backend("omni-local-7b")
        backend.complete("hi", response_schema={"type": "object"})
        assert recorder.kwargs["response_format"] == {"type": "json_object"}

    def test_anthropic_request_omits_temperature_and_sets_output_format(self):
        response = SimpleNamespace(
            content=[SimpleNamespace(text="{}")],
            model="m",
            usage=SimpleNamespace(input_tokens=3, output_tokens=2),
        )
        recorder = _Recorder(response)
        backend = AnthropicBackend()
        backend.cache = None
        backend._client = SimpleNamespace(messages=recorder)
        backend.complete("hi", system="s", response_schema={"type": "object"})
        assert "temperature" not in recorder.kwargs
        assert recorder.kwargs["output_config"]["format"]["type"] == "json_schema"
        assert (
            recorder.kwargs["model"] == load_settings().providers["anthropic"].default
        )


class TestConfiguredModelIds:
    def test_default_ids_appear_in_sdk_type_hints(self):
        """Config IDs for anthropic/openai must come from the installed SDK hints."""
        import anthropic.types
        import openai.types.shared.chat_model as chat_model

        sdk = {
            "anthropic": set(typing.get_args(anthropic.types.Model.__args__[0])),
            "openai": set(typing.get_args(chat_model.ChatModel)),
        }
        for provider, ids in sdk.items():
            configured = load_settings().providers[provider]
            for model in (configured.default, *configured.fallbacks):
                assert model in ids, f"{model} not in {provider} SDK hints"


class TestResolveModel:
    def test_explicit_model_wins_without_listing(self):
        def boom():
            raise AssertionError("listed")

        assert resolve_model("openai", requested="my-model", lister=boom) == "my-model"

    def test_without_a_key_falls_back_to_config_default(self, monkeypatch):
        monkeypatch.delenv("OPENAI_API_KEY", raising=False)
        monkeypatch.setattr(
            catalog, "list_provider_models", lambda *a, **k: pytest.fail("network")
        )
        assert resolve_model("openai") == load_settings().providers["openai"].default

    def test_with_a_key_prefers_the_first_listed_configured_model(self):
        cfg = load_settings().providers["anthropic"]
        listed = [cfg.fallbacks[0], "something-else"]
        assert (
            resolve_model("anthropic", api_key="k", lister=lambda: listed)
            == (cfg.fallbacks[0])
        )

    def test_listing_failure_or_no_match_uses_default(self):
        default = load_settings().providers["openai"].default

        def fail():
            raise TimeoutError

        assert resolve_model("openai", api_key="k", lister=fail) == default
        assert resolve_model("openai", api_key="k", lister=lambda: ["zzz"]) == default

    def test_ollama_never_lists(self):
        assert resolve_model("ollama", api_key="k") == "llama3.1"

    def test_create_backend_resolves_through_the_provider_list(self, monkeypatch):
        fallback = load_settings().providers["anthropic"].fallbacks[0]
        monkeypatch.setenv("ANTHROPIC_API_KEY", "k")
        monkeypatch.setattr(catalog, "list_provider_models", lambda *a, **k: [fallback])
        assert create_backend("anthropic").model == fallback
        assert create_backend("anthropic", model="pinned").model == "pinned"

    def test_backend_defaults_come_from_config(self):
        cfg = load_settings().providers
        assert OpenAIBackend().model == cfg["openai"].default
        assert AnthropicBackend().model == cfg["anthropic"].default
        assert OllamaBackend().model == cfg["ollama"].default
