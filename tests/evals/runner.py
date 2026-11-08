import json
from pathlib import Path
from typing import Any

from haris.llm.correlation import LLMCorrelator
from haris.llm.enrichment import FindingEnricher
from haris.llm.triage import SmartTriager
from haris.llm.variant_analysis import VariantAnalyzer
from haris.models import Severity, Target
from tests.evals.fake_provider import FakeProvider, fenced_blocks, make_finding

CASES_FILE = Path(__file__).parent / "cases.json"
TARGET = Target(base_url="https://example.com")
INJECTION_MARKER = "ignore previous instructions"


def load_cases() -> list[dict[str, Any]]:
    cases: list[dict[str, Any]] = json.loads(CASES_FILE.read_text("utf-8"))
    return cases


def _findings(spec: list[dict[str, str]]) -> list:
    return [
        make_finding(
            entry["id"],
            severity=Severity(entry.get("severity", "high")),
            evidence=entry.get("evidence", "reflected payload"),
        )
        for entry in spec
    ]


def run_case(case: dict[str, Any]) -> dict[str, Any]:
    """Run one stage against a canned model reply; return observable metrics."""
    provider = FakeProvider(lambda _request: case["output"])
    findings = _findings(case["findings"])
    before = [f.model_dump() for f in findings]
    stage = case["stage"]
    if stage == "triage":
        triager = SmartTriager(provider)
        items = [t.finding_id for t in triager.triage_findings(findings)]
        report = triager.last_report
    elif stage == "false_positives":
        correlator = LLMCorrelator(provider)
        items = [v["finding_id"] for v in correlator.detect_false_positives(findings)]
        report = correlator.last_report
    elif stage == "chains":
        correlator = LLMCorrelator(provider)
        items = [c.chain_id for c in correlator.identify_attack_chains(findings)]
        report = correlator.last_report
    elif stage == "enrichment":
        enricher = FindingEnricher(provider)
        items = list(enricher.batch_enrich(findings, TARGET))
        report = enricher.last_report
    elif stage == "variants":
        analyzer = VariantAnalyzer(provider)
        items = [s.url_pattern for s in analyzer.suggest_variants(findings[0], TARGET)]
        report = analyzer.last_report
    else:
        raise ValueError(f"unknown stage {stage!r}")
    prompt = provider.requests[0].messages[-1]["content"]
    outside = prompt
    for block in fenced_blocks(prompt):
        outside = outside.replace(block, "")
    return {
        "items": len(items),
        "ids": items,
        "errors": len(report.errors),
        "statuses": report.statuses,
        "findings_unchanged": [f.model_dump() for f in findings] == before,
        "injection_fenced": INJECTION_MARKER not in outside,
    }


def main() -> None:
    for case in load_cases():
        metrics = run_case(case)
        failed = [
            key
            for key, want in case["expect"].items()
            if (
                any(metrics["statuses"].get(k) != v for k, v in want.items())
                if key == "statuses"
                else metrics[key] != want
            )
        ]
        print(f"{'FAIL' if failed else 'ok  '} {case['name']} {failed or ''}")


if __name__ == "__main__":
    main()
