import ast
import logging
import traceback
from collections.abc import Callable
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import httpx
import litellm
import pytest

from haris.llm.base import create_backend, get_available_backends
from haris.llm.litellm_backend import (
    LiteLLMBackend,
    LLMConfigError,
    scrub,
    table_cost,
    validate_model,
)
from haris.llm.settings import load_settings
from haris.verify.llm_verdict import run_llm_verdicts
from haris.verify.settings import load_verify_settings
from tests.evals.fake_provider import FakeClock
from tests.test_verify_llm import answer, make_case

SRC = Path(__file__).resolve().parents[1] / "src" / "haris"
BEDROCK = "bedrock/us.anthropic.claude-sonnet-5"
KEY = "sk-test-123"


def reply(text: str = "pong") -> SimpleNamespace:
    return SimpleNamespace(
        choices=[SimpleNamespace(message=SimpleNamespace(content=text))],
        model="served-model",
        usage=SimpleNamespace(prompt_tokens=3, completion_tokens=2, total_tokens=5),
    )


def http_error(
    cls: Any, status: int, message: str = "boom", **headers: str
) -> Exception:
    response = httpx.Response(
        status, headers=headers, request=httpx.Request("POST", "http://gw.test")
    )
    return cls(message, "openai", "alias", response=response)  # type: ignore[no-any-return]


def rate_limited(**headers: str) -> Exception:
    return http_error(litellm.RateLimitError, 429, **headers)


def unavailable() -> Exception:
    return http_error(litellm.ServiceUnavailableError, 503)


def bad_request() -> Exception:
    return http_error(litellm.BadRequestError, 400)


class Wire:
    """Stands in for litellm.completion: scripted answers, recorded kwargs."""

    def __init__(self, *answers: Any) -> None:
        self.answers = list(answers) or [reply()]
        self.calls: list[dict[str, Any]] = []

    def __call__(self, **kwargs: Any) -> Any:
        self.calls.append(kwargs)
        item = self.answers.pop(0) if len(self.answers) > 1 else self.answers[0]
        if isinstance(item, Exception):
            raise item
        return item


@pytest.fixture
def wire(monkeypatch: pytest.MonkeyPatch) -> Callable[..., Wire]:
    monkeypatch.delenv("LITELLM_API_KEY", raising=False)

    def install(*answers: Any) -> Wire:
        fake = Wire(*answers)
        monkeypatch.setattr(litellm, "completion", fake)
        return fake

    return install


def backend(model: str = BEDROCK, **kwargs: Any) -> LiteLLMBackend:
    made = LiteLLMBackend(model=model, **kwargs)
    made.cache = None
    return made


class TestStaticImportAudit:
    def test_only_the_backend_module_imports_litellm(self):
        importers: dict[str, set[str]] = {}
        for path in SRC.rglob("*.py"):
            for node in ast.walk(ast.parse(path.read_text("utf-8"))):
                if isinstance(node, ast.Import):
                    names = {a.name.split(".")[0] for a in node.names}
                elif isinstance(node, ast.ImportFrom) and node.level == 0:
                    names = {(node.module or "").split(".")[0]}
                else:
                    continue
                for name in names & {"litellm", "anthropic", "openai"}:
                    importers.setdefault(name, set()).add(path.name)
        assert importers == {"litellm": {"litellm_backend.py"}}


class TestCallParameters:
    @pytest.mark.parametrize(
        "send",
        [
            lambda b: b.complete("hi"),
            lambda b: b.complete_messages([{"role": "user", "content": "hi"}]),
            lambda b: b.complete("hi", system="s", response_schema={"type": "object"}),
        ],
        ids=["prompt", "messages", "structured"],
    )
    def test_every_request_carries_the_fixed_parameters(self, wire, send):
        assert load_settings().runtime.timeout_s == 60
        fake = wire()
        send(backend())
        assert len(fake.calls) == 1
        call = fake.calls[0]
        assert (call["num_retries"], call["timeout"], call["drop_params"]) == (
            0,
            60,
            True,
        )
        assert call["model"] == BEDROCK

    def test_timeout_follows_the_runtime_setting(self, wire):
        fake = wire()
        made = backend()
        runtime = load_settings().runtime.model_copy(update={"timeout_s": 7})
        made.settings = load_settings().model_copy(update={"runtime": runtime})
        made.complete("hi")
        assert fake.calls[0]["timeout"] == 7

    def test_system_message_comes_first_and_usage_is_mapped(self, wire):
        fake = wire()
        response = backend().complete("hi", system="be brief", max_tokens=99)
        assert fake.calls[0]["messages"] == [
            {"role": "system", "content": "be brief"},
            {"role": "user", "content": "hi"},
        ]
        assert fake.calls[0]["max_tokens"] == 99
        assert (response.text, response.model, response.token_count) == (
            "pong",
            "served-model",
            5,
        )


class TestModelValidation:
    @pytest.mark.parametrize("model", ["", "claude-sonnet-5", "bedrock/", "/alias"])
    def test_bad_model_lists_the_three_examples(self, wire, model):
        fake = wire()
        with pytest.raises(LLMConfigError) as raised:
            create_backend("litellm", model=model)
        for example in (
            "bedrock/<inference profile id>",
            "openai/<gateway alias>",
            "ollama_chat/<tag>",
        ):
            assert example in str(raised.value)
        assert "llm.model" in str(raised.value)
        assert fake.calls == []

    @pytest.mark.parametrize(
        "model", [BEDROCK, "openai/my-gateway-alias", "ollama_chat/llama3.1"]
    )
    def test_valid_model_is_sent_unchanged(self, wire, model):
        fake = wire()
        create_backend("litellm", model=model).complete("hi")
        assert fake.calls[0]["model"] == model
        assert validate_model(model) == model

    def test_is_available_needs_a_valid_model(self):
        assert backend().is_available()
        assert not backend("").is_available()
        assert not backend("claude-sonnet-5").is_available()

    def test_listing_reports_the_reason(self):
        (entry,) = get_available_backends(BEDROCK)
        assert (entry["name"], entry["available"], entry["reason"]) == (
            "litellm",
            True,
            "",
        )
        (entry,) = get_available_backends("")
        assert entry["available"] is False
        assert "bedrock/<inference profile id>" in entry["reason"]

    def test_listing_reports_a_missing_package(self, monkeypatch):
        monkeypatch.setattr("importlib.util.find_spec", lambda _name: None)
        (entry,) = get_available_backends(BEDROCK)
        assert entry["available"] is False
        assert "litellm" in entry["reason"]


class TestEndpointAndKey:
    def test_gateway_call_passes_base_and_key(self, wire, monkeypatch):
        monkeypatch.setenv("GW_KEY", KEY)
        fake = wire()
        made = backend(
            "openai/alias", api_base="https://gw.internal:4000", api_key_env="GW_KEY"
        )
        made.complete("hi")
        assert fake.calls[0]["api_base"] == "https://gw.internal:4000"
        assert fake.calls[0]["api_key"] == KEY

    def test_direct_bedrock_call_passes_neither(self, wire):
        fake = wire()
        backend().complete("hi")
        assert "api_base" not in fake.calls[0]
        assert "api_key" not in fake.calls[0]

    def test_an_empty_key_variable_is_not_passed(self, wire, monkeypatch):
        monkeypatch.setenv("LITELLM_API_KEY", "")
        fake = wire()
        backend().complete("hi")
        assert "api_key" not in fake.calls[0]


class TestSecretInAnError:
    def test_scrub_replaces_the_key_only_when_there_is_one(self):
        assert scrub(f"bad key {KEY}!", KEY) == "bad key [REDACTED]!"
        assert scrub("plain", None) == "plain"
        assert scrub("plain", "") == "plain"

    def test_retry_warning_does_not_log_the_key(self, wire, monkeypatch, caplog):
        monkeypatch.setenv("GW_KEY", KEY)
        fake = wire(
            http_error(litellm.RateLimitError, 429, f"quota for {KEY}"), reply()
        )
        made = backend("openai/alias", api_key_env="GW_KEY")
        made.sleep = FakeClock().sleep
        with caplog.at_level(logging.WARNING):
            made.complete("hi")
        assert len(fake.calls) == 2
        assert "[REDACTED]" in caplog.text
        assert KEY not in caplog.text


class TestScrubAtTheSource:
    @pytest.fixture(autouse=True)
    def key(self, monkeypatch):
        monkeypatch.setenv("GW_KEY", KEY)

    def gateway(self) -> LiteLLMBackend:
        made = backend("openai/alias", api_key_env="GW_KEY")
        made.sleep = FakeClock().sleep
        return made

    def test_key_in_the_message_is_redacted_on_the_same_exception(self, wire):
        error = http_error(litellm.BadRequestError, 400, f"bad key {KEY}")
        wire(error)
        with pytest.raises(litellm.BadRequestError) as raised:
            self.gateway().complete("hi")
        assert raised.value is error
        assert KEY not in str(error) and "[REDACTED]" in str(error)
        assert error.status_code == 400  # type: ignore[attr-defined]  # litellm sets it

    def test_key_in_a_chained_cause_or_context_is_redacted(self, wire):
        cause = RuntimeError(f"upstream rejected {KEY}")
        context = ValueError(f"while handling {KEY}")
        error = http_error(litellm.BadRequestError, 400)
        error.__cause__ = cause
        cause.__context__ = context
        context.__context__ = error  # cycle
        wire(error)
        with pytest.raises(litellm.BadRequestError):
            self.gateway().complete("hi")
        assert KEY not in str(cause) and KEY not in str(context)

    def test_status_code_survives_so_a_429_is_still_retried(self, wire):
        fake = wire(http_error(litellm.RateLimitError, 429, f"quota {KEY}"), reply())
        assert self.gateway().complete("hi").text == "pong"
        assert len(fake.calls) == 2

    def test_traceback_text_has_no_key(self, wire):
        wire(http_error(litellm.BadRequestError, 400, f"bad key {KEY}"))
        with pytest.raises(litellm.BadRequestError) as raised:
            self.gateway().complete("hi")
        assert KEY not in "".join(traceback.format_exception(raised.value))

    def test_exception_is_untouched_when_no_key_is_set(self, wire, monkeypatch):
        monkeypatch.delenv("GW_KEY")
        error = http_error(litellm.BadRequestError, 400, "mentions sk-other")
        wire(error)
        with pytest.raises(litellm.BadRequestError):
            self.gateway().complete("hi")
        assert "sk-other" in str(error)

    def test_verdict_stage_log_and_error_text_have_no_key(self, wire, caplog):
        wire(http_error(litellm.BadRequestError, 400, f"bad key {KEY}"))
        case = make_case()
        with caplog.at_level(logging.DEBUG):
            errors = run_llm_verdicts([case], self.gateway(), load_verify_settings())
        assert errors and "[REDACTED]" in "".join(errors)
        assert KEY not in "".join(errors)
        assert KEY not in caplog.text
        assert "LLM verdict for" in caplog.text


class TestSchemaRequest:
    def test_response_format_is_json_schema_named_haris_output(self, wire):
        schema = {"type": "object", "properties": {"a": {"type": "string"}}}
        fake = wire()
        backend().complete("hi", response_schema=schema)
        assert fake.calls[0]["response_format"] == {
            "type": "json_schema",
            "json_schema": {"name": "haris_output", "schema": schema, "strict": False},
        }

    def test_plain_request_has_no_response_format(self, wire):
        fake = wire()
        backend().complete("hi")
        assert "response_format" not in fake.calls[0]


class TestUnsupportedFormat:
    def test_prose_reply_stores_invalid_and_keeps_the_tier(self, wire):
        fake = wire(reply("I think this is real."))
        case = make_case()
        tier = case.canonical.verification.tier
        run_llm_verdicts([case], backend(), load_verify_settings())
        assert "response_format" in fake.calls[0]
        assessment = case.canonical.verification.llm
        assert assessment is not None and assessment.status == "invalid"
        assert case.canonical.verification.tier == tier

    def test_a_route_that_obeys_the_format_is_judged(self, wire):
        case = make_case()
        wire(reply(answer(case.canonical.finding_id)))
        run_llm_verdicts([case], backend(), load_verify_settings())
        assessment = case.canonical.verification.llm
        assert assessment is not None and assessment.status == "ok"


class TestRetrySequence:
    @pytest.mark.parametrize(
        ("errors", "calls", "error"),
        [
            ([rate_limited()], 2, None),
            ([unavailable()] * 4, 4, litellm.ServiceUnavailableError),
            ([bad_request()], 1, litellm.BadRequestError),
            (
                [rate_limited(**{"Retry-After": "3600"})],
                1,
                litellm.RateLimitError,
            ),
        ],
        ids=["429-then-200", "503-x4", "400", "429-retry-after-over-cap"],
    )
    def test_calls_made(self, wire, errors, calls, error):
        assert load_settings().runtime.max_retries == 3
        fake = wire(*errors, *([] if error else [reply()]))
        made = backend()
        made.sleep = FakeClock().sleep
        if error:
            with pytest.raises(error):
                made.complete("hi")
        else:
            assert made.complete("hi").text == "pong"
        assert len(fake.calls) == calls

    def test_retry_after_within_the_cap_is_waited_out(self, wire):
        clock = FakeClock()
        wire(rate_limited(**{"Retry-After": "5"}), reply())
        made = backend()
        made.sleep = clock.sleep
        made.complete("hi")
        assert len(clock.slept) == 1 and clock.slept[0] >= 5


class TestTableCost:
    def test_returns_the_sum_of_prompt_and_output_price(self, monkeypatch):
        monkeypatch.setattr(litellm, "cost_per_token", lambda **_k: (3.0, 0.5))
        assert table_cost(BEDROCK, 1_000_000, 0) == 3.5

    def test_none_when_the_model_is_not_priced(self):
        assert table_cost("openai/alias", 1000, 1000) is None

    def test_none_on_any_failure(self, monkeypatch):
        def boom(**_k: Any) -> None:
            raise RuntimeError("table unreadable")

        monkeypatch.setattr(litellm, "cost_per_token", boom)
        assert table_cost(BEDROCK, 1, 1) is None
