import json
import os
from pathlib import Path

import pytest

from haris.models import AuthConfig, ScanContext, VerificationTier
from haris.scanners.garak_scanner import GarakScanner

from .adapter_support import (
    BOTH,
    FAKE_GARAK,
    GARAK_FAIL,
    GARAK_PASS,
    SECRET,
    Tool,
    eval_entry,
    run,
)
from .ai_support import net_with


@pytest.fixture
def garak(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Tool:
    tool = Tool(tmp_path, "garak", FAKE_GARAK)
    monkeypatch.setenv("PATH", f"{tool.bin}{os.pathsep}{os.environ['PATH']}")
    return tool


class TestGarakParser:
    @pytest.mark.parametrize(
        ("fails", "total", "confidence"),
        [(0, 10, None), (1, 10, 0.55), (10, 10, 0.95)],
        ids=["absent", "one-in-ten", "all"],
    )
    def test_fail_rate_to_confidence(self, fails, total, confidence) -> None:
        findings = GarakScanner().parse_results(eval_entry(fails, total))
        if confidence is None:
            assert findings == []
            return
        assert [f.confidence_score for f in findings] == [pytest.approx(confidence)]
        assert findings[0].verification.tier is VerificationTier.UNVERIFIED

    def test_golden_report_with_failures(self) -> None:
        findings = GarakScanner().parse_results(GARAK_FAIL, "http://127.0.0.1/chat")
        assert {f.parameter for f in findings} == {
            "promptinject.HijackLongPrompt:promptinject.AttackRogueString",
            "latentinjection.LatentInjectionTranslationEnFr:base.TriggerListDetector",
        }
        assert {f.owasp_category for f in findings} == {"LLM01:2025 - Prompt Injection"}
        assert {f.confidence_score for f in findings} == {0.95}
        assert {f.scanner for f in findings} == {"garak"}

    def test_golden_report_without_failures(self) -> None:
        assert GarakScanner().parse_results(GARAK_PASS) == []

    def test_malformed_and_foreign_lines_are_skipped(self) -> None:
        raw = "\n".join(["{not json", '{"entry_type": "attempt"}', eval_entry(5, 10)])
        assert len(GarakScanner().parse_results(raw)) == 1

    def test_non_numeric_counts_are_skipped(self) -> None:
        raw = json.dumps({"entry_type": "eval", "fails": "3", "total_evaluated": 4})
        assert GarakScanner().parse_results(raw) == []


class TestGarakRun:
    def test_argv_and_config(self, garak: Tool) -> None:
        garak.plan(report=GARAK_FAIL)
        result = run(
            GarakScanner, auth=AuthConfig(method="header", header_value=SECRET), **BOTH
        )
        (call,) = garak.calls
        argv = call["argv"][1:]
        assert argv[:4] == ["--target_type", "rest", "-G", argv[3]]
        assert argv[argv.index("--spec") + 1] == (
            "probes.promptinject.HijackLongPrompt,"
            "probes.latentinjection.LatentInjectionTranslationEnFr"
        )
        assert argv[argv.index("--parallel_attempts") + 1] == "1"
        assert not any("ADAPTER-SECRET" in a for a in argv)
        rest = json.loads(call["rest"])["rest"]["RestGenerator"]
        assert rest["uri"] == "https://example.com/v1/chat/completions"
        assert rest["req_template_json_object"]["messages"][0]["content"] == "$INPUT"
        assert rest["req_template_json_object"]["max_tokens"] == 256
        assert rest["req_template_json_object"]["model"] == "m1"
        assert rest["headers"]["Authorization"] == SECRET
        assert json.loads(call["run"])["run"]["soft_probe_prompt_cap"] == 50
        assert call["mode"] == 0o600
        assert len(result.findings) == 2
        assert result.errors == []

    def test_prompt_cap_follows_the_option(self, garak: Tool) -> None:
        run(GarakScanner, max_prompts=7, max_tokens_per_prompt=32, **BOTH)
        (call,) = garak.calls
        assert json.loads(call["run"])["run"]["soft_probe_prompt_cap"] == 7
        body = json.loads(call["rest"])["rest"]["RestGenerator"][
            "req_template_json_object"
        ]
        assert body["max_tokens"] == 32

    def test_allow_listed_extra_args_are_appended(self, garak: Tool) -> None:
        run(GarakScanner, extra_args=["--seed", "3"], **BOTH)
        assert garak.calls[0]["argv"][-2:] == ["--seed", "3"]

    @pytest.mark.parametrize(
        "extra",
        [["--generator_options", "x"], ["--seed", "3; rm -rf /"], ["-p", "dan"]],
    )
    def test_other_flags_and_unsafe_values_are_refused(
        self, garak: Tool, extra
    ) -> None:
        result = run(GarakScanner, extra_args=extra, **BOTH)
        assert garak.calls == []
        assert result.errors and result.findings == []

    def test_probes_outside_the_allow_list_are_refused(self, garak: Tool) -> None:
        result = run(GarakScanner, probes=["dan.Dan_11_0"], **BOTH)
        assert garak.calls == []
        assert "not allowed" in result.errors[0]

    def test_chosen_allowed_probe_is_used(self, garak: Tool) -> None:
        run(GarakScanner, probes=["promptinject.HijackLongPrompt"], **BOTH)
        argv = garak.calls[0]["argv"]
        assert argv[argv.index("--spec") + 1] == "probes.promptinject.HijackLongPrompt"

    @pytest.mark.parametrize(
        "options",
        [{}, {"active": True}, {"authorised": True}],
        ids=["none", "active", "auth"],
    )
    def test_nothing_runs_without_both_flags(self, garak: Tool, options) -> None:
        result = run(GarakScanner, **options)
        assert garak.calls == []
        assert result.errors == [] and result.metadata["skipped"]

    def test_no_chat_endpoint_is_a_skip(self, garak: Tool) -> None:
        net = net_with({})
        scanner = GarakScanner(dict(BOTH))
        result = scanner.scan(net.client.target, ScanContext(http=net.client))
        assert garak.calls == [] and result.errors == []
        assert "no AI chat endpoint" in result.metadata["skipped"][0]

    def test_timeout_keeps_partial_output(self, garak: Tool) -> None:
        garak.plan(report=GARAK_FAIL, sleep=30)
        result = run(GarakScanner, timeout=2, **BOTH)
        assert len(result.findings) == 2
        assert "timed out" in result.errors[0]

    def test_credentials_are_redacted_in_output_and_errors(self, garak: Tool) -> None:
        entry = json.loads(eval_entry(5, 10))
        entry["detector"] = f"leaks.{SECRET}"
        garak.plan(report=json.dumps(entry), stderr=SECRET, exit=1)
        result = run(
            GarakScanner, auth=AuthConfig(method="header", header_value=SECRET), **BOTH
        )
        blob = json.dumps(
            [
                result.raw_output,
                result.errors,
                [f.model_dump(mode="json") for f in result.findings],
            ]
        )
        assert "ADAPTER-SECRET" not in blob
        assert len(result.findings) == 1

    def test_failed_run_without_report_is_an_error(self, garak: Tool) -> None:
        garak.plan(report="", stderr="boom", exit=3)
        result = run(GarakScanner, **BOTH)
        assert "code 3" in result.errors[0] and result.findings == []
