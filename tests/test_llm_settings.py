import yaml

from haris.config.loader import _build_config
from haris.config.paths import resolve_config_file
from haris.llm.settings import SETTINGS_FILE, load_settings
from haris.models import LLMConfig


def test_kept_blocks_still_load_and_vendor_blocks_are_gone():
    raw = yaml.safe_load(resolve_config_file(SETTINGS_FILE).read_text("utf-8"))
    assert {"runtime", "budget", "pricing", "redaction", "limits"} <= raw.keys()
    assert not {"providers", "capabilities"} & raw.keys()
    cfg = load_settings()
    assert cfg.runtime.timeout_s == 60
    assert cfg.runtime.max_retries == 3
    assert cfg.budget.max_tokens == 200_000
    assert cfg.pricing == []
    assert cfg.redaction.emails is False
    assert cfg.limits.batch_size == 30
    assert not hasattr(cfg, "providers") and not hasattr(cfg, "capabilities")


def test_llm_config_defaults_name_litellm_and_no_model():
    cfg = LLMConfig()
    assert (cfg.backend, cfg.model, cfg.api_base, cfg.api_key_env) == (
        "litellm",
        "",
        "",
        "LITELLM_API_KEY",
    )


def test_loader_reads_endpoint_key_variable_and_routing():
    config = _build_config(
        {
            "llm": {
                "model": "openai/alias",
                "api_base": "https://gw.internal:4000",
                "api_key_env": "GW_KEY",
                "model_routing": {"summary": "ollama_chat/llama3.1"},
            }
        }
    )
    assert config.llm.backend == "litellm"
    assert config.llm.api_base == "https://gw.internal:4000"
    assert config.llm.api_key_env == "GW_KEY"
    assert config.llm.model_routing == {"summary": "ollama_chat/llama3.1"}
