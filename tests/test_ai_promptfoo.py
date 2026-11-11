import json
import os
from pathlib import Path

import pytest
import yaml

from haris.ai_security.adapters import tool_config
from haris.models import AuthConfig, Severity, VerificationTier
from haris.scanners.promptfoo_scanner import (
    MalformedOutputError,
    PromptfooScanner,
    prompt_budget,
)

from .adapter_support import (
    BOTH,
    FAKE_PROMPTFOO,
    PROMPTFOO_EVAL,
    SECRET,
    Tool,
    pf_json,
    run,
)


@pytest.fixture
def promptfoo(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Tool:
    tool = Tool(tmp_path, "promptfoo", FAKE_PROMPTFOO)
    monkeypatch.setenv("PATH", f"{tool.bin}{os.pathsep}{os.environ['PATH']}")
    return tool


class TestPromptfooParser:
    def test_one_failure_in_four(self) -> None:
        raw = pf_json("prompt-injection", [False, True, True, True])
        (found,) = PromptfooScanner().parse_results(raw, "http://127.0.0.1/chat")
        assert found.confidence_score == pytest.approx(0.625)
        assert found.owasp_category.startswith("LLM01:2026")
        assert found.verification.tier is VerificationTier.UNVERIFIED
        assert found.parameter == "prompt-injection"

    def test_golden_results(self) -> None:
        (found,) = PromptfooScanner().parse_results(PROMPTFOO_EVAL)
        assert found.parameter == "prompt-extraction"
        assert found.confidence_score == pytest.approx(0.75)
        assert found.owasp_category.startswith("LLM08:2026")
        assert found.cwe_id == "CWE-200"

    def test_one_finding_per_plugin(self) -> None:
        raw = json.loads(pf_json("hijacking", [False, False]))
        raw["results"]["results"] += json.loads(pf_json("prompt-extraction", [False]))[
            "results"
        ]["results"]
        findings = PromptfooScanner().parse_results(json.dumps(raw))
        assert sorted(f.parameter for f in findings) == [
            "hijacking",
            "prompt-extraction",
        ]
        assert {f.confidence_score for f in findings} == {0.95}

    def test_errored_tests_are_not_failures(self) -> None:
        assert (
            PromptfooScanner().parse_results(pf_json("hijacking", [False], reason=2))
            == []
        )

    def test_all_passing_gives_nothing(self) -> None:
        assert (
            PromptfooScanner().parse_results(pf_json("hijacking", [True, True])) == []
        )

    def test_unknown_plugin_uses_the_default_mapping(self) -> None:
        (found,) = PromptfooScanner().parse_results(pf_json("something-new", [False]))
        assert found.severity is Severity.LOW
        assert found.owasp_category.startswith("LLM01:2026")

    @pytest.mark.parametrize(
        "raw",
        [PROMPTFOO_EVAL[:500], "", "[]", '{"results": {"results": "x"}}'],
        ids=["truncated", "empty", "wrong-shape", "not-a-list"],
    )
    def test_malformed_output_raises(self, raw) -> None:
        with pytest.raises(MalformedOutputError):
            PromptfooScanner().parse_results(raw)


class TestPromptfooRun:
    def test_two_step_argv_and_config(self, promptfoo: Tool) -> None:
        promptfoo.plan(results=PROMPTFOO_EVAL, eval_exit=100)
        result = run(
            PromptfooScanner,
            auth=AuthConfig(method="header", header_value=SECRET),
            **BOTH,
        )
        generate, evaluate = promptfoo.calls
        assert generate["argv"][1:3] == ["redteam", "generate"]
        assert evaluate["argv"][1] == "eval"
        assert "--no-share" in evaluate["argv"] and "--no-write" in evaluate["argv"]
        assert evaluate["argv"][evaluate["argv"].index("--max-concurrency") + 1] == "1"
        assert not any(
            "ADAPTER-SECRET" in a for a in generate["argv"] + evaluate["argv"]
        )
        assert evaluate["env"] == {
            "PROMPTFOO_DISABLE_TELEMETRY": "1",
            "PROMPTFOO_DISABLE_UPDATE": "1",
            "PROMPTFOO_DISABLE_SHARING": "1",
        }
        config = yaml.safe_load(generate["config"])
        target = config["targets"][0]
        assert target["id"] == "http"
        assert target["config"]["url"] == "https://example.com/v1/chat/completions"
        assert target["config"]["headers"]["Authorization"] == SECRET
        assert target["config"]["body"]["messages"][0]["content"] == "{{prompt}}"
        assert config["redteam"]["plugins"] == [
            "prompt-extraction",
            "hijacking",
            "system-prompt-override",
            "ascii-smuggling",
        ]
        assert config["redteam"]["numTests"] == 12
        assert generate["mode"] == 0o600
        assert len(result.findings) == 1
        assert result.errors == []

    @pytest.mark.parametrize("cap", [1, 3, 4, 50])
    def test_code_h2_num_tests_stay_within_cap(self, cap: int) -> None:
        plugins = tool_config("promptfoo").default_selection
        chosen, num_tests = prompt_budget(cap, list(plugins))
        assert num_tests * len(chosen) <= cap
        if cap < len(plugins):
            assert chosen == list(plugins[:cap]) and num_tests == 1
        else:
            assert chosen == list(plugins) and num_tests == cap // len(plugins)

    def test_provider_option_is_passed_to_generation_only(
        self, promptfoo: Tool
    ) -> None:
        promptfoo.plan(results=pf_json("hijacking", [True]))
        run(PromptfooScanner, provider="ollama:chat:llama3", **BOTH)
        generate, evaluate = promptfoo.calls
        assert generate["argv"][-3:-1] == ["--provider", "ollama:chat:llama3"]
        assert "--provider" not in evaluate["argv"]

    @pytest.mark.parametrize("provider", ["--evil", "a b", "x;y"])
    def test_bad_provider_is_refused(self, promptfoo: Tool, provider) -> None:
        result = run(PromptfooScanner, provider=provider, **BOTH)
        assert promptfoo.calls == [] and result.errors

    def test_plugins_outside_the_allow_list_are_refused(self, promptfoo: Tool) -> None:
        result = run(PromptfooScanner, plugins=["harmful:hate"], **BOTH)
        assert promptfoo.calls == []
        assert "not allowed" in result.errors[0]

    def test_extra_args_apply_to_eval(self, promptfoo: Tool) -> None:
        promptfoo.plan(results=pf_json("hijacking", [True]))
        run(PromptfooScanner, extra_args=["--delay", "500"], **BOTH)
        generate, evaluate = promptfoo.calls
        assert evaluate["argv"][-2:] == ["--delay", "500"]
        assert "--delay" not in generate["argv"]

    def test_truncated_json_is_an_error_without_findings(self, promptfoo: Tool) -> None:
        promptfoo.plan(results=PROMPTFOO_EVAL[:500], eval_exit=100)
        result = run(PromptfooScanner, **BOTH)
        assert result.findings == []
        assert "promptfoo" in result.errors[0] and "parsed" in result.errors[0]

    def test_generation_failure_stops_before_eval(self, promptfoo: Tool) -> None:
        promptfoo.plan(results="", generate_exit=1, generate_stderr="no OPENAI_API_KEY")
        result = run(PromptfooScanner, **BOTH)
        assert [c["step"] for c in promptfoo.calls] == ["generate"]
        assert "test generation" in result.errors[0]

    def test_timeout_keeps_partial_output(self, promptfoo: Tool) -> None:
        promptfoo.plan(results=PROMPTFOO_EVAL, sleep=30)
        result = run(PromptfooScanner, timeout=2, **BOTH)
        assert len(result.findings) == 1
        assert "timed out" in result.errors[0]

    def test_credentials_are_redacted(self, promptfoo: Tool) -> None:
        promptfoo.plan(results=pf_json(f"x-{SECRET}", [False]), eval_exit=100)
        result = run(
            PromptfooScanner,
            auth=AuthConfig(method="header", header_value=SECRET),
            **BOTH,
        )
        blob = json.dumps(
            [
                result.raw_output,
                result.errors,
                [f.model_dump(mode="json") for f in result.findings],
            ]
        )
        assert "ADAPTER-SECRET" not in blob

    @pytest.mark.parametrize("options", [{}, {"active": True}], ids=["none", "active"])
    def test_nothing_runs_without_both_flags(self, promptfoo: Tool, options) -> None:
        result = run(PromptfooScanner, **options)
        assert promptfoo.calls == [] and result.metadata["skipped"]
