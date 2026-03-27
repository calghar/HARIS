import json
from unittest.mock import MagicMock

from src.llm.correlation import LLMCorrelator
from src.llm.enrichment import FindingEnricher
from src.llm.enrichment_prompts import EnrichmentPromptBuilder
from src.llm.triage import SmartTriager
from src.llm.variant_analysis import VariantAnalyzer, VariantSuggestion
from src.models import Confidence, Finding, Severity, Target
from src.models.enrichment import (
    AttackChain,
    EnrichedFinding,
    TriageContext,
    TriagedFinding,
)
from src.models.llm import LLMResponse


def _mock_backend(response_text: str) -> MagicMock:
    """Create a mock LLM backend that returns the given text."""
    backend = MagicMock()
    backend.complete.return_value = LLMResponse(
        text=response_text,
        model="test-model",
        usage={"prompt_tokens": 10, "completion_tokens": 20, "total_tokens": 30},
    )
    return backend


def _make_finding(
    title: str = "Test SQLi",
    severity: Severity = Severity.HIGH,
    finding_id: str = "F001",
    url: str = "https://example.com/search",
    **kwargs,
) -> Finding:
    return Finding(
        title=title,
        description="SQL injection in search parameter",
        severity=severity,
        confidence=Confidence.CONFIRMED,
        url=url,
        scanner="test",
        tags=["sql_injection"],
        finding_id=finding_id,
        **kwargs,
    )


def _make_target() -> Target:
    return Target(base_url="https://example.com")


class TestEnrichmentModels:
    def test_enriched_finding_defaults(self):
        ef = EnrichedFinding(finding_id="F001")
        assert ef.attack_narrative == ""
        assert ef.variant_suggestions == []

    def test_attack_chain(self):
        chain = AttackChain(
            chain_id="C1",
            name="SQLi to data exfil",
            description="Combine SQLi with exposed DB port",
            finding_ids=["F001", "F002"],
            total_impact="full database compromise",
            likelihood="high",
        )
        assert len(chain.finding_ids) == 2

    def test_triaged_finding(self):
        tf = TriagedFinding(
            finding_id="F001",
            original_severity=Severity.HIGH,
            adjusted_severity=Severity.CRITICAL,
            exploitability_score=9,
            business_priority=10,
            triage_rationale="Directly exploitable",
            recommended_timeline="immediate",
        )
        assert tf.adjusted_severity == Severity.CRITICAL


class TestFindingEnricher:
    def test_should_enrich_above_threshold(self):
        enricher = FindingEnricher(
            _mock_backend("{}"),
            severity_threshold="high",
        )
        assert enricher.should_enrich(_make_finding(severity=Severity.CRITICAL))
        assert enricher.should_enrich(_make_finding(severity=Severity.HIGH))
        assert not enricher.should_enrich(_make_finding(severity=Severity.MEDIUM))
        assert not enricher.should_enrich(_make_finding(severity=Severity.LOW))

    def test_enrich_finding_success(self):
        response_json = json.dumps(
            {
                "attack_narrative": "Attacker sends malicious SQL",
                "business_impact_assessment": "Data breach risk",
                "exploitation_complexity": "low",
                "false_positive_likelihood": "low",
                "related_cwes": ["CWE-89"],
                "attack_chain_position": "initial_access",
                "variant_suggestions": ["Check /api/search too"],
            }
        )
        backend = _mock_backend(response_json)
        enricher = FindingEnricher(backend, severity_threshold="high")

        result = enricher.enrich_finding(
            _make_finding(),
            _make_target(),
            ["Other finding"],
        )
        assert result is not None
        assert result.finding_id == "F001"
        assert result.exploitation_complexity == "low"
        assert "CWE-89" in result.related_cwes
        backend.complete.assert_called_once()

    def test_enrich_finding_below_threshold(self):
        backend = _mock_backend("{}")
        enricher = FindingEnricher(backend, severity_threshold="high")
        result = enricher.enrich_finding(
            _make_finding(severity=Severity.LOW),
            _make_target(),
        )
        assert result is None
        backend.complete.assert_not_called()

    def test_enrich_finding_bad_json(self):
        backend = _mock_backend("not valid json at all")
        enricher = FindingEnricher(backend, severity_threshold="info")
        result = enricher.enrich_finding(
            _make_finding(),
            _make_target(),
        )
        assert result is None

    def test_batch_enrich(self):
        response_json = json.dumps(
            {
                "attack_narrative": "test",
                "business_impact_assessment": "test",
                "exploitation_complexity": "medium",
                "false_positive_likelihood": "low",
                "related_cwes": [],
                "attack_chain_position": "standalone",
                "variant_suggestions": [],
            }
        )
        backend = _mock_backend(response_json)
        enricher = FindingEnricher(backend, severity_threshold="high")

        findings = [
            _make_finding(finding_id="F001", severity=Severity.HIGH),
            _make_finding(finding_id="F002", severity=Severity.LOW),
            _make_finding(finding_id="F003", severity=Severity.CRITICAL),
        ]

        results = enricher.batch_enrich(findings, _make_target())
        # Only HIGH and CRITICAL should be enriched
        assert "F001" in results
        assert "F002" not in results
        assert "F003" in results
        assert backend.complete.call_count == 2


class TestLLMCorrelator:
    def test_identify_attack_chains(self):
        chains_json = json.dumps(
            [
                {
                    "chain_id": "C1",
                    "name": "SQLi + DB exposure",
                    "description": "Chain description",
                    "finding_ids": ["F001", "F002"],
                    "total_impact": "full compromise",
                    "likelihood": "high",
                },
            ]
        )
        backend = _mock_backend(chains_json)
        correlator = LLMCorrelator(backend)

        findings = [
            _make_finding(finding_id="F001"),
            _make_finding(finding_id="F002", title="Exposed MySQL"),
        ]
        chains = correlator.identify_attack_chains(findings)
        assert len(chains) == 1
        assert chains[0].name == "SQLi + DB exposure"
        assert "F001" in chains[0].finding_ids

    def test_identify_chains_single_finding(self):
        backend = _mock_backend("[]")
        correlator = LLMCorrelator(backend)
        chains = correlator.identify_attack_chains([_make_finding()])
        assert chains == []
        backend.complete.assert_not_called()

    def test_detect_false_positives(self):
        fp_json = json.dumps(
            [
                {
                    "finding_id": "F002",
                    "false_positive_likelihood": "high",
                    "rationale": "Weak evidence",
                },
            ]
        )
        backend = _mock_backend(fp_json)
        correlator = LLMCorrelator(backend)

        fps = correlator.detect_false_positives([_make_finding()])
        assert len(fps) == 1
        assert fps[0]["finding_id"] == "F002"

    def test_bad_json_returns_empty(self):
        backend = _mock_backend("not json")
        correlator = LLMCorrelator(backend)
        assert (
            correlator.identify_attack_chains(
                [_make_finding(), _make_finding(finding_id="F002")],
            )
            == []
        )


class TestSmartTriager:
    def test_triage_findings(self):
        triage_json = json.dumps(
            [
                {
                    "finding_id": "F001",
                    "exploitability_score": 9,
                    "business_priority": 10,
                    "adjusted_severity": "critical",
                    "triage_rationale": "Directly exploitable SQLi",
                    "recommended_timeline": "immediate",
                },
            ]
        )
        backend = _mock_backend(triage_json)
        triager = SmartTriager(backend)

        findings = [_make_finding()]
        results = triager.triage_findings(findings, {"industry": "fintech"})
        assert len(results) == 1
        assert results[0].adjusted_severity == Severity.CRITICAL
        assert results[0].recommended_timeline == "immediate"

    def test_triage_empty(self):
        backend = _mock_backend("[]")
        triager = SmartTriager(backend)
        assert triager.triage_findings([], None) == []
        backend.complete.assert_not_called()

    def test_triage_with_context_object(self):
        triage_json = json.dumps([])
        backend = _mock_backend(triage_json)
        triager = SmartTriager(backend)
        ctx = TriageContext(
            industry="healthcare",
            data_sensitivity="phi",
            compliance_frameworks=["hipaa"],
        )
        triager.triage_findings([_make_finding()], ctx)
        backend.complete.assert_called_once()


class TestVariantAnalyzer:
    def test_suggest_variants(self):
        variants_json = json.dumps(
            [
                {
                    "description": "Check /api/search endpoint",
                    "rationale": "Same parameter pattern",
                    "url_pattern": "/api/search?q=",
                },
            ]
        )
        backend = _mock_backend(variants_json)
        analyzer = VariantAnalyzer(backend)

        suggestions = analyzer.suggest_variants(
            _make_finding(),
            _make_target(),
        )
        assert len(suggestions) == 1
        assert suggestions[0].url_pattern == "/api/search?q="

    def test_variant_suggestion_to_dict(self):
        vs = VariantSuggestion(
            description="test",
            rationale="because",
            url_pattern="/test",
        )
        d = vs.to_dict()
        assert d["description"] == "test"
        assert d["url_pattern"] == "/test"


class TestEnrichmentPromptBuilder:
    def test_system_prompt(self):
        system = EnrichmentPromptBuilder.system()
        assert "penetration tester" in system

    def test_enrich_finding_prompt(self):
        system, prompt = EnrichmentPromptBuilder.enrich_finding(
            _make_finding(),
            _make_target(),
            ["Other vuln"],
        )
        assert "Test SQLi" in prompt
        assert "example.com" in prompt
        assert "JSON" in prompt

    def test_identify_attack_chains_prompt(self):
        _, prompt = EnrichmentPromptBuilder.identify_attack_chains(
            [_make_finding(), _make_finding(finding_id="F002")],
        )
        assert "attack chain" in prompt.lower()
        assert "F001" in prompt

    def test_triage_prompt_with_context(self):
        ctx = TriageContext(
            industry="fintech",
            compliance_frameworks=["pci-dss"],
        )
        system, prompt = EnrichmentPromptBuilder.triage_findings(
            [_make_finding()],
            ctx,
        )
        assert "fintech" in prompt
        assert "pci-dss" in prompt

    def test_suggest_variants_prompt(self):
        _, prompt = EnrichmentPromptBuilder.suggest_variants(
            _make_finding(),
            _make_target(),
        )
        assert "variant" in prompt.lower()
        assert "manual review" in prompt.lower()
