import logging
from pathlib import Path
from typing import Any

import litellm
import pytest

from haris.cli import main
from haris.config.loader import load_config
from haris.core.runner import ScanRunner
from haris.llm.base import create_backend, create_backend_from_config
from haris.llm.litellm_backend import LiteLLMBackend, LLMConfigError
from haris.llm.router import ModelRouter
from haris.models import LLMConfig
from tests.test_engine_pipeline import Probe

BEDROCK = "bedrock/us.anthropic.claude-sonnet-5"
HAIKU = "bedrock/us.anthropic.claude-haiku-5-5"
LEGACY = ["anthropic", "openai", "ollama", "bedrock"]


@pytest.fixture(autouse=True)
def no_network(monkeypatch: pytest.MonkeyPatch) -> None:
    def refuse(**_kwargs: Any) -> None:
        pytest.fail("a request was sent")

    monkeypatch.setattr(litellm, "completion", refuse)


@pytest.fixture
def cli(monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
    monkeypatch.setattr("haris.cli_scan._save_session_to_db", lambda *_a, **_k: None)
    monkeypatch.setattr(ScanRunner, "_build_scanners", lambda _self: [Probe("nuclei")])
    monkeypatch.chdir(tmp_path)

    def run(*flags: str, config: str = "") -> int:
        args = ["--url", "https://example.com", "--yes", "--verify", "off"]
        args += ["--formats", "json", "--output", str(tmp_path / "out")]
        if config:
            path = tmp_path / "haris.yaml"
            path.write_text(config)
            args += ["--config", str(path)]
        return main([*args, *flags])

    return run


def assert_names_litellm_and_model(text: str) -> None:
    assert "litellm" in text and "llm.model" in text


class TestLegacyNameRejected:
    @pytest.mark.parametrize("name", LEGACY)
    def test_create_backend_names_litellm_and_llm_model(self, name):
        with pytest.raises(LLMConfigError) as raised:
            create_backend(name, model=BEDROCK)
        assert_names_litellm_and_model(str(raised.value))

    def test_registry_holds_only_litellm_and_creates_it(self):
        made = create_backend("litellm", model="openai/alias")
        assert isinstance(made, LiteLLMBackend) and made.model == "openai/alias"

    def test_llm_backend_flag_exits_3(self, cli, capsys):
        assert cli("--llm-enrich", "--llm-backend", "anthropic") == 3
        assert_names_litellm_and_model(capsys.readouterr().out)

    def test_backend_in_config_exits_3(self, cli, capsys):
        config = "llm:\n  backend: openai\n  enrichment_enabled: true\n"
        assert cli(config=config) == 3
        assert_names_litellm_and_model(capsys.readouterr().out)

    def test_ask_backend_flag_exits_3(self, cli, capsys):
        argv = ["llm", "ask", "--scan-id", "x", "--question", "q"]
        assert main([*argv, "--backend", "ollama"]) == 3
        assert_names_litellm_and_model(capsys.readouterr().err)

    def test_litellm_flag_creates_the_backend_from_config(self, cli):
        config = "llm:\n  model: openai/alias\n  api_base: https://gw.internal:4000\n"
        assert cli("--llm-enrich", "--llm-backend", "litellm", config=config) == 0

    def test_runner_builds_the_configured_endpoint(self, cli, tmp_path):
        path = tmp_path / "gw.yaml"
        path.write_text(
            "llm:\n  model: openai/alias\n  api_base: https://gw.internal:4000\n"
            "  api_key_env: GW_KEY\n  enrichment_enabled: true\n"
        )
        runner = ScanRunner(
            target=load_config(path).target, config=load_config(path), llm_enrich=True
        )
        backend, _ = runner._create_llm_enrichment()
        assert (backend.model, backend.api_base, backend.api_key_env) == (
            "openai/alias",
            "https://gw.internal:4000",
            "GW_KEY",
        )


class TestModelRequiredAtTheCli:
    def test_blank_model_exits_3_with_the_examples(self, cli, capsys):
        assert cli("--llm-enrich") == 3
        out = capsys.readouterr().out
        assert "bedrock/<inference profile id>" in out and "ollama_chat/<tag>" in out

    def test_ask_without_model_exits_3(self, cli, capsys):
        argv = ["llm", "ask", "--scan-id", "x", "--question", "q"]
        assert main(argv) == 3
        assert "openai/<gateway alias>" in capsys.readouterr().err

    def test_model_argument_overrides_the_config_model(self):
        llm = LLMConfig(model=BEDROCK, api_key_env="GW_KEY")
        made = create_backend_from_config(llm, None, "ollama_chat/llama3.1")
        assert (made.model, made.name) == ("ollama_chat/llama3.1", "litellm")


class TestRouting:
    @pytest.mark.parametrize(
        ("routing", "model"),
        [
            ({"summary": HAIKU}, HAIKU),
            ({"summary": "claude-haiku"}, BEDROCK),
            ({}, BEDROCK),
        ],
        ids=["valid-string", "invalid-string", "no-routing"],
    )
    def test_summary_model(self, routing, model):
        default = create_backend("litellm", model=BEDROCK)
        assert ModelRouter(default, routing).for_task("summary").model == model

    def test_invalid_routed_value_is_logged_and_the_default_is_used(self, caplog):
        default = create_backend("litellm", model=BEDROCK)
        router = ModelRouter(default, {"summary": "claude-haiku"})
        with caplog.at_level(logging.WARNING):
            assert router.for_task("summary") is default
        assert "claude-haiku" in caplog.text

    def test_routed_task_shares_endpoint_key_variable_and_budget(self):
        default = create_backend(
            "litellm",
            model="openai/alias",
            api_base="https://gw.internal:4000",
            api_key_env="GW_KEY",
        )
        router = ModelRouter(default, {"triage": "openai/small"})
        routed = router.for_task("triage")
        assert isinstance(routed, LiteLLMBackend)
        assert (routed.api_base, routed.api_key_env) == (
            "https://gw.internal:4000",
            "GW_KEY",
        )
        assert routed.budget is router.budget is default.budget
