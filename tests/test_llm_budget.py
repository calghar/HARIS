import json
import threading
import time

import pytest

from haris.llm.budget import BudgetExceededError, LLMBudget
from haris.llm.correlation import LLMCorrelator
from haris.llm.enrichment import FindingEnricher
from haris.llm.settings import BudgetSettings, Price, load_settings
from haris.llm.triage import SmartTriager
from haris.models import Target
from tests.evals.fake_provider import FakeProvider, make_finding, prompt_ids

TARGET = Target(base_url="https://example.com")


def _ok_enrichment(_request):
    return json.dumps({"attack_narrative": "n", "exploitation_complexity": "low"})


class TestTokenBudget:
    def test_small_budget_marks_the_remainder_skipped_budget(self):
        """A 1,000-token budget over 50 findings flags the remainder."""
        provider = FakeProvider(_ok_enrichment, tokens_per_call=300)
        provider.budget = LLMBudget(BudgetSettings(max_tokens=1000, max_cost_usd=None))
        findings = [make_finding(f"F{i:02d}") for i in range(50)]
        enricher = FindingEnricher(provider)

        batch = enricher.run_batch(findings, TARGET)

        report = batch.report
        ok = report.ids_with("ok")
        assert len(report.statuses) == 50
        assert 1 <= len(ok) < 50
        assert sorted(report.skipped_budget + ok) == sorted(
            f.finding_id for f in findings
        )
        assert sorted(batch.items) == sorted(ok)
        assert len(provider.requests) == len(ok)
        assert provider.budget.used_tokens <= 1000
        assert enricher.last_report is report

    def test_output_allowance_is_clamped_to_the_remaining_budget(self):
        provider = FakeProvider(_ok_enrichment, tokens_per_call=50)
        provider.budget = LLMBudget(BudgetSettings(max_tokens=1000, max_cost_usd=None))
        provider.complete("hi", max_tokens=4096)
        assert provider.requests[0].max_tokens <= 1000

    def test_no_findings_are_dropped_beyond_the_batch_size(self):
        """Regression: chunks replace the old silent cut to 25/30 findings."""
        findings = [make_finding(f"F{i:02d}") for i in range(50)]

        def answer(request):
            return json.dumps(
                {"items": [{"finding_id": i} for i in prompt_ids(request)]}
            )

        provider = FakeProvider(answer)
        triaged = SmartTriager(provider).triage_findings(findings)
        assert len(triaged) == 50
        assert len(provider.requests) == 2

    def test_chunk_stage_reports_skipped_budget_per_finding(self):
        findings = [make_finding(f"F{i:02d}") for i in range(50)]
        provider = FakeProvider(lambda r: '{"items": []}', tokens_per_call=2000)
        provider.budget = LLMBudget(BudgetSettings(max_tokens=2500, max_cost_usd=None))
        correlator = LLMCorrelator(provider)
        assert correlator.detect_false_positives(findings) == []
        statuses = set(correlator.last_report.statuses.values())
        assert statuses == {"ok", "skipped_budget"}
        assert len(correlator.last_report.statuses) == 50

    def test_failed_call_releases_its_reservation(self):
        def boom(_request):
            raise ValueError("provider exploded")

        provider = FakeProvider(boom)
        provider.budget = LLMBudget(BudgetSettings(max_tokens=1000, max_cost_usd=None))
        with pytest.raises(ValueError):
            provider.complete("hi")
        assert provider.budget.used_tokens == 0
        provider.budget.reserve(10, 100, "m")  # would block if still reserved


class TestCostBudget:
    def _budget(self, **price):
        settings = load_settings().model_copy(
            update={"pricing": [Price(match="priced-*", **price)]}
        )
        return LLMBudget(BudgetSettings(max_tokens=None, max_cost_usd=0.01), settings)

    def test_cost_cap_stops_priced_models(self):
        budget = self._budget(input_per_mtok=5.0, output_per_mtok=5.0)
        reservation = budget.reserve(1000, 4000, "priced-a")
        assert reservation.max_tokens < 4000
        budget.settle(
            reservation,
            {"prompt_tokens": 1000, "completion_tokens": reservation.max_tokens},
        )
        with pytest.raises(BudgetExceededError):
            budget.reserve(1000, 4000, "priced-a")

    def test_unknown_price_means_token_cap_only(self):
        budget = self._budget(input_per_mtok=1000.0, output_per_mtok=1000.0)
        for _ in range(5):
            r = budget.reserve(100_000, 4000, "unpriced-model")
            budget.settle(r, {"prompt_tokens": 100_000, "completion_tokens": 4000})
        assert budget.used_cost == 0.0


class TestBoundedConcurrency:
    def test_gate_limits_in_flight_calls(self):
        settings = load_settings().model_copy(
            update={
                "runtime": load_settings().runtime.model_copy(
                    update={"max_concurrency": 2}
                )
            }
        )
        lock = threading.Lock()
        active = peak = 0

        def slow(request):
            nonlocal active, peak
            with lock:
                active += 1
                peak = max(peak, active)
            time.sleep(0.02)
            with lock:
                active -= 1
            return "{}"

        provider = FakeProvider(slow)
        provider.settings = settings
        FindingEnricher(provider).batch_enrich(
            [make_finding(f"F{i}") for i in range(12)], TARGET
        )
        assert len(provider.requests) == 12
        assert peak == 2


class TestRouterBudget:
    def test_router_shares_one_budget_with_default_and_routed_backends(self):
        from unittest.mock import patch

        from haris.llm.router import ModelRouter

        default = FakeProvider(_ok_enrichment)
        routed = FakeProvider(_ok_enrichment)
        with patch("haris.llm.router.create_backend", return_value=routed):
            router = ModelRouter(default, {"triage": "other-model"})
            assert router.for_task("triage") is routed
        assert default.budget is router.budget is routed.budget
        assert router.budget.max_tokens == load_settings().budget.max_tokens
