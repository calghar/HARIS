from pathlib import Path

import pytest

from haris.ai_security.findings import ai_finding
from haris.ai_security.owasp_ai import Mappings, load_mappings
from haris.core.decorators import check_registry
from haris.core.owasp import AI_RISKS, map_ai_risk
from haris.core.profiles import PROFILES, get_profile
from haris.models.owasp import AgenticRisk, LlmRisk, McpRisk

SRC = Path(__file__).resolve().parent.parent / "src" / "haris"
NEW_CHECKS = {
    "sri_checks",
    "cache_checks",
    "method_checks",
    "redirect_checks",
    "graphql_checks",
    "openapi_checks",
    "listing_checks",
    "dns_checks",
}

# (check kind, OWASP ids, CWE) — the "Passive check mapping" scenario outline.
PASSIVE_MAPPING = [
    ("unauthenticated_inference", ["LLM06:2026", "ASI03"], "CWE-306"),
    ("mcp_unauthenticated", ["MCP07:2025", "MCP09:2025"], "CWE-306"),
    ("provider_key_in_bundle", ["LLM02:2026"], "CWE-798"),
    ("system_prompt_in_bundle", ["LLM08:2026"], "CWE-200"),
    ("verbose_provider_error", ["LLM02:2026"], "CWE-209"),
    ("plaintext_mcp_transport", ["MCP07:2025"], "CWE-319"),
]
LLM_2026 = {
    "LLM01:2026 - Prompt Injection",
    "LLM02:2026 - Sensitive Information Disclosure",
    "LLM03:2026 - Excessive Agency",
    "LLM04:2026 - Supply Chain",
    "LLM05:2026 - Data and Model Poisoning",
    "LLM06:2026 - Unbounded Consumption",
    "LLM07:2026 - Misinformation",
    "LLM08:2026 - Hidden Context Exposure",
    "LLM09:2026 - Vector and Embedding Weaknesses",
    "LLM10:2026 - Improper Output Handling",
}
# Check kind -> (2025 number, 2026 id) for the checks whose LLM id moved.
RENUMBERED = [
    ("unauthenticated_inference", "LLM10", "LLM06:2026"),
    ("provider_key_in_bundle", "LLM02", "LLM02:2026"),
    ("system_prompt_in_bundle", "LLM07", "LLM08:2026"),
    ("verbose_provider_error", "LLM02", "LLM02:2026"),
    ("prompt_injection_canary", "LLM01", "LLM01:2026"),
    ("output_handling_xss", "LLM05", "LLM10:2026"),
    ("excessive_agency_schema", "LLM06", "LLM03:2026"),
]
STATIC_MAPPING = [
    ("tool_description_injection", ["MCP03:2025", "MCP06:2025", "ASI04"]),
    ("hidden_unicode", ["MCP03:2025", "ASI04"]),
    ("excessive_agency_schema", ["LLM03:2026", "MCP05:2025", "ASI05"]),
    ("toxic_flow", ["ASI02", "MCP10:2025"]),
]


class TestRiskTables:
    def test_each_list_has_ten_ids(self) -> None:
        assert len(LlmRisk) == len(AgenticRisk) == len(McpRisk) == 10
        assert len(AI_RISKS) == 30

    def test_lookup_returns_the_named_risk(self) -> None:
        assert map_ai_risk("LLM01:2026") is LlmRisk.LLM01
        assert map_ai_risk("ASI10") is AgenticRisk.ASI10
        assert map_ai_risk("MCP03:2025") is McpRisk.MCP03
        assert map_ai_risk("LLM01") is None
        assert map_ai_risk(f"LLM01:{2025}") is None

    def test_llm_list_is_the_2026_edition(self) -> None:
        assert {r.value for r in LlmRisk} == LLM_2026
        assert all(map_ai_risk(r.value.split(" - ")[0]) is r for r in LlmRisk)

    def test_unverified_note_is_present_in_the_mcp_table(self) -> None:
        assert "[UNVERIFIED]" in (SRC / "models" / "owasp.py").read_text()


class TestMappingTable:
    @pytest.mark.parametrize(("kind", "owasp", "cwe"), PASSIVE_MAPPING)
    def test_passive_check_mapping(self, kind, owasp, cwe) -> None:
        finding = ai_finding(kind, url="https://x.test/")
        assert [t for t in finding.tags if t != "ai"] == owasp
        assert finding.cwe_id == cwe
        assert finding.owasp_category.startswith(owasp[0])

    @pytest.mark.parametrize(("kind", "owasp"), STATIC_MAPPING)
    def test_static_heuristic_mapping(self, kind, owasp) -> None:
        finding = ai_finding(kind, url="https://x.test/")
        assert [t for t in finding.tags if t != "ai"] == owasp

    @pytest.mark.parametrize(("kind", "old", "new"), RENUMBERED)
    def test_llm_ids_moved_from_2025_to_2026(self, kind, old, new) -> None:
        finding = ai_finding(kind, url="https://x.test/")
        assert new in finding.tags
        assert f"{old}:2025" not in finding.tags
        assert finding.owasp_category.startswith(new)

    def test_unknown_owasp_id_is_rejected(self) -> None:
        raw = load_mappings().model_dump(mode="json")
        raw["checks"]["toxic_flow"]["owasp"] = ["LLM99:2025"]
        with pytest.raises(ValueError, match="LLM99:2025"):
            Mappings.model_validate(raw)

    def test_findings_start_unverified_with_explicit_confidence(self) -> None:
        finding = ai_finding("unauthenticated_admin", url="https://x.test/")
        assert finding.verification.tier.value == "unverified"
        assert finding.confidence_score == 0.85
        assert finding.vuln_class == "ai_unauthenticated_admin"

    def test_references_point_at_the_owasp_lists(self) -> None:
        finding = ai_finding("tool_description_injection", url="https://x.test/")
        assert len(finding.references) == 2


class TestProfiles:
    @pytest.mark.parametrize("name", ["quick", "pre-launch", "full"])
    def test_profiles_include_the_new_checks(self, name) -> None:
        assert get_profile(name).scanner_set() >= NEW_CHECKS

    def test_new_check_names_are_registered_checks(self) -> None:
        assert set(check_registry()) >= NEW_CHECKS

    def test_ai_security_profile_uses_registered_scanners(self) -> None:
        profile = PROFILES["ai-security"]
        assert {"ai_security", "garak", "promptfoo"} <= profile.scanner_set()
