from datetime import UTC, datetime, timedelta
from email.utils import format_datetime

import anthropic
import httpx2
import pytest

from haris.llm.backend import LLMRequest
from haris.llm.retry import Retrier, retry_after_seconds
from haris.llm.settings import RuntimeSettings
from tests.evals.fake_provider import FakeClock, FakeProvider


def _status_error(status: int, **headers: str) -> anthropic.APIStatusError:
    response = httpx2.Response(
        status, headers=headers, request=httpx2.Request("POST", "http://provider.test")
    )
    cls = anthropic.RateLimitError if status == 429 else anthropic.APIStatusError
    return cls("boom", response=response, body=None)


def _flaky(errors: list[Exception]):
    queue = list(errors)

    def handler(_request: LLMRequest) -> str:
        if queue:
            raise queue.pop(0)
        return "recovered"

    return handler


class TestRetryAfter:
    def test_429_with_retry_after_waits_at_least_that_long_then_succeeds(self):
        clock = FakeClock()
        provider = FakeProvider(
            _flaky([_status_error(429, **{"Retry-After": "2"})]), clock=clock
        )
        assert provider.complete("hi").text == "recovered"
        assert len(provider.requests) == 2
        assert len(clock.slept) == 1 and clock.slept[0] >= 2

    def test_http_date_retry_after_is_honoured(self):
        when = datetime.now(UTC) + timedelta(seconds=30)
        exc = _status_error(429, **{"Retry-After": format_datetime(when)})
        assert 25 <= (retry_after_seconds(exc) or 0) <= 30

    def test_retry_after_beyond_the_cap_gives_up(self):
        clock = FakeClock()
        provider = FakeProvider(
            _flaky([_status_error(429, **{"Retry-After": "3600"})]), clock=clock
        )
        with pytest.raises(anthropic.RateLimitError):
            provider.complete("hi")
        assert clock.slept == [] and len(provider.requests) == 1


class TestBackoff:
    def test_jittered_backoff_stays_within_the_exponential_window(self):
        cfg = RuntimeSettings(max_retries=3, backoff_base_s=1.0, backoff_max_s=30.0)
        slept: list[float] = []
        calls = 0

        def always_503() -> None:
            nonlocal calls
            calls += 1
            raise _status_error(503)

        retrier = Retrier(cfg, sleep=slept.append, uniform=lambda lo, hi: hi)
        with pytest.raises(anthropic.APIStatusError):
            retrier.call(always_503)
        assert calls == 4
        assert slept == [1.0, 2.0, 4.0]

    def test_real_jitter_varies_between_zero_and_window(self):
        cfg = RuntimeSettings(backoff_base_s=2.0)
        delays = {Retrier(cfg).delay(2, _status_error(500)) for _ in range(20)}
        assert len(delays) > 1 and all(0 <= (d or 0) <= 8 for d in delays)

    @pytest.mark.parametrize("status", [400, 401, 403, 404, 422])
    def test_client_errors_are_not_retried(self, status):
        clock = FakeClock()
        provider = FakeProvider(_flaky([_status_error(status)] * 3), clock=clock)
        with pytest.raises(anthropic.APIStatusError):
            provider.complete("hi")
        assert clock.slept == [] and len(provider.requests) == 1


class TestStructuredFallback:
    def test_provider_rejecting_the_schema_is_retried_without_it(self):
        provider = FakeProvider(_flaky([_status_error(400)]))
        response = provider.complete("hi", response_schema={"type": "object"})
        assert response.text == "recovered"
        assert [r.response_schema for r in provider.requests] == [
            {"type": "object"},
            None,
        ]
