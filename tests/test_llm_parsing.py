import json

import pytest

from haris.llm.parsing import extract_json, parse_items, parse_object
from haris.llm.schemas import EnrichmentOut, TriageOut
from haris.llm.triage import SmartTriager
from tests.evals.fake_provider import FakeProvider, make_finding, prompt_ids


def _triage_item(finding_id: str, score: object = 7) -> dict[str, object]:
    return {
        "finding_id": finding_id,
        "exploitability_score": score,
        "business_priority": 6,
        "adjusted_severity": "High",
        "triage_rationale": "reachable",
        "recommended_timeline": "this_sprint",
    }


class TestSharedParser:
    def test_one_malformed_item_is_dropped_and_recorded(self):
        """Batch of 5 with 1 malformed returns 4 valid items and 1 error."""
        payload = [_triage_item(f"F{i}") for i in range(5)]
        payload[2]["exploitability_score"] = 99
        result = parse_items(json.dumps(payload), TriageOut)
        assert [i.finding_id for i in result.items] == ["F0", "F1", "F3", "F4"]
        assert len(result.errors) == 1
        assert result.errors[0].startswith("item 2:")

    @pytest.mark.parametrize(
        "wrap",
        [
            lambda body: body,
            lambda body: f"```json\n{body}\n```",
            lambda body: f"```\n{body}\n```",
            lambda body: f"Here is the result:\n```json\n{body}\n```\nDone.",
            lambda body: f"Sure! {body} Hope that helps.",
            lambda body: json.dumps({"items": json.loads(body)}),
        ],
        ids=["bare", "json-fence", "plain-fence", "prose-fence", "prose", "envelope"],
    )
    def test_fenced_and_bare_json_both_parse(self, wrap):
        body = json.dumps([_triage_item("F0"), _triage_item("F1")])
        result = parse_items(wrap(body), TriageOut)
        assert len(result.items) == 2 and result.ok

    @pytest.mark.parametrize(
        "text",
        ["", "no json here", '[{"finding_id": "F0"', '{"items": "nope"}', "42"],
    )
    def test_unusable_output_yields_error_not_exception(self, text):
        result = parse_items(text, TriageOut)
        assert result.items == [] and len(result.errors) == 1

    def test_non_object_elements_are_item_errors(self):
        result = parse_items(json.dumps([_triage_item("F0"), "x", 3]), TriageOut)
        assert len(result.items) == 1 and len(result.errors) == 2

    def test_enum_like_values_are_normalised_or_rejected(self):
        ok = parse_object('{"exploitation_complexity": " HIGH "}', EnrichmentOut)
        assert ok.items[0].exploitation_complexity == "high"
        bad = parse_object('{"exploitation_complexity": "trivial"}', EnrichmentOut)
        assert bad.items == [] and bad.errors

    def test_extract_json_prefers_first_value(self):
        assert extract_json('noise {"a": 1} tail [2]') == {"a": 1}


class TestStagesUseSharedParser:
    def test_triage_keeps_valid_items_around_a_bad_one(self):
        findings = [make_finding(f"F{i}") for i in range(5)]

        def answer(request):
            items = [_triage_item(i) for i in prompt_ids(request)]
            items[1]["business_priority"] = "urgent"
            return "```json\n" + json.dumps(items) + "\n```"

        triager = SmartTriager(FakeProvider(answer))
        result = triager.triage_findings(findings)
        assert len(result) == 4
        assert result[0].adjusted_severity.value == "high"
        assert len(triager.last_report.errors) == 1

    def test_unknown_finding_ids_are_dropped_from_triage(self):
        findings = [make_finding("F0")]
        provider = FakeProvider(
            lambda r: json.dumps([_triage_item("F0"), _triage_item("GHOST")])
        )
        triager = SmartTriager(provider)
        assert [t.finding_id for t in triager.triage_findings(findings)] == ["F0"]
        assert "unknown finding GHOST" in triager.last_report.errors
