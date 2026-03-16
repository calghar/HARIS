"""Tests for the LLM adapter layer."""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

from src.llm.base import BACKEND_REGISTRY, BaseLLMBackend
from src.llm.prompts import PromptBuilder
from src.llm.qa import ReportQA
from src.models import (
    Confidence,
    Finding,
    LLMResponse,
    RiskPosture,
    ScanSession,
    Severity,
    Target,
)


class MockBackend(BaseLLMBackend):
    """Deterministic backend for testing."""

    name = "mock"

    def __init__(self):
        self.last_prompt = ""
        self.last_system = ""
        self.call_count = 0

    def complete(
        self,
        prompt: str,
        *,
        system: str = "",
        temperature: float = 0.2,
        max_tokens: int = 2048,
    ) -> LLMResponse:
        self.last_prompt = prompt
        self.last_system = system
        self.call_count += 1
        return LLMResponse(
            text=f"Mock answer #{self.call_count}",
            model="mock-1",
            usage={"prompt_tokens": 100, "completion_tokens": 50, "total_tokens": 150},
        )


def _make_session() -> ScanSession:
    """Create a minimal ScanSession for testing."""
    target = Target(base_url="https://example.com")
    findings = [
        Finding(
            title="SQL Injection in search",
            description="The search parameter is vulnerable to SQL injection.",
            severity=Severity.CRITICAL,
            confidence=Confidence.CONFIRMED,
            url="https://example.com/search?q=test",
            parameter="q",
            remediation="Use parameterised queries.",
            scanner="wapiti",
            tags=["sql_injection"],
            finding_id="f001",
            owasp_category="A05:2025 - Injection",
        ),
        Finding(
            title="Missing HSTS header",
            description="The response lacks HSTS.",
            severity=Severity.MEDIUM,
            confidence=Confidence.CONFIRMED,
            url="https://example.com",
            remediation="Add Strict-Transport-Security header.",
            scanner="header_checks",
            tags=["missing_hsts"],
            finding_id="f002",
            owasp_category="A04:2025 - Cryptographic Failures",
        ),
    ]
    return ScanSession(
        session_id="test-001",
        target=target,
        started_at="2025-02-22T14:30:00+00:00",
        finished_at="2025-02-22T14:35:00+00:00",
        profile_name="quick",
        scanners_used=["wapiti", "header_checks"],
        all_findings=findings,
        risk_posture=RiskPosture.POOR,
        risk_posture_text="Multiple significant vulnerabilities found.",
    )


class TestPromptBuilder:
    def test_system_prompt_contains_rules(self):
        system = PromptBuilder.system_prompt()
        assert "Never fabricate" in system
        assert "finding IDs" in system

    def test_summarize_report_executive(self):
        session = _make_session()
        system, prompt = PromptBuilder.summarize_report(session, "executive")
        assert "executive" in prompt.lower() or "non-technical" in prompt.lower()
        assert "f001" in prompt
        assert "f002" in prompt
        assert "example.com" in prompt

    def test_summarize_report_technical(self):
        session = _make_session()
        system, prompt = PromptBuilder.summarize_report(session, "technical")
        assert "technical" in prompt.lower()

    def test_explain_finding(self):
        session = _make_session()
        finding = session.all_findings[0]
        system, prompt = PromptBuilder.explain_finding(finding, session)
        assert "SQL Injection" in prompt
        assert "f001" in prompt

    def test_freeform_question(self):
        session = _make_session()
        system, prompt = PromptBuilder.freeform_question(
            session, "What are the main risks?"
        )
        assert "What are the main risks?" in prompt
        assert "report data" in prompt.lower()

    def test_remediation_plan_jira(self):
        session = _make_session()
        system, prompt = PromptBuilder.propose_remediation_plan(session, "jira")
        assert "Jira" in prompt

    def test_generate_test_cases(self):
        session = _make_session()
        system, prompt = PromptBuilder.generate_test_cases(session, "pytest")
        assert "pytest" in prompt
        assert "CI" in prompt

    def test_context_includes_owasp_2025(self):
        session = _make_session()
        system, prompt = PromptBuilder.freeform_question(session, "test")
        assert "2025" in prompt


class TestReportQA:
    def test_ask_calls_backend(self):
        backend = MockBackend()
        qa = ReportQA(backend=backend)
        session = _make_session()
        response = qa.ask(session, "What's the biggest risk?")
        assert response.text.startswith("Mock answer")
        assert backend.call_count == 1
        assert "biggest risk" in backend.last_prompt

    def test_summarize(self):
        backend = MockBackend()
        qa = ReportQA(backend=backend)
        session = _make_session()
        qa.summarize(session, audience="developer")
        assert backend.call_count == 1

    def test_explain_finding_exists(self):
        backend = MockBackend()
        qa = ReportQA(backend=backend)
        session = _make_session()
        qa.explain_finding(session, "f001")
        assert backend.call_count == 1

    def test_explain_finding_not_found(self):
        backend = MockBackend()
        qa = ReportQA(backend=backend)
        session = _make_session()
        response = qa.explain_finding(session, "nonexistent")
        assert "not found" in response.text
        assert backend.call_count == 0  # should not call LLM

    def test_remediation_plan(self):
        backend = MockBackend()
        qa = ReportQA(backend=backend)
        session = _make_session()
        qa.remediation_plan(session, format="jira")
        assert backend.call_count == 1

    def test_filter_findings(self):
        backend = MockBackend()
        qa = ReportQA(backend=backend)
        session = _make_session()
        qa.filter_findings(session, "authentication issues")
        assert backend.call_count == 1

    def test_from_json_file(self):
        session = _make_session()
        report = {
            "meta": {
                "session_id": "test-001",
                "target": "https://example.com",
                "profile": "quick",
                "started_at": "2025-02-22T14:30:00",
                "finished_at": "2025-02-22T14:35:00",
                "scanners_used": ["wapiti"],
            },
            "risk_posture": {"level": "poor", "description": "Bad"},
            "findings": [f.to_dict() for f in session.all_findings],
        }

        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False
        ) as f:
            json.dump(report, f)
            f.flush()
            path = Path(f.name)

        try:
            backend = MockBackend()
            qa, loaded_session = ReportQA.from_json_file(path, backend)
            assert loaded_session.session_id == "test-001"
            assert len(loaded_session.all_findings) == 2
            assert loaded_session.risk_posture == RiskPosture.POOR
        finally:
            path.unlink()


class TestLLMResponse:
    def test_token_count(self):
        resp = LLMResponse(
            text="test",
            usage={"total_tokens": 42},
        )
        assert resp.token_count == 42

    def test_empty_usage(self):
        resp = LLMResponse(text="test")
        assert resp.token_count == 0


class TestBackendRegistry:
    def test_known_backends(self):
        assert "openai" in BACKEND_REGISTRY
        assert "anthropic" in BACKEND_REGISTRY
        assert "ollama" in BACKEND_REGISTRY
