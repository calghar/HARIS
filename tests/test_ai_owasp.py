from pathlib import Path

import pytest

from haris import checks  # noqa: F401  # importing registers the checks
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
    ("unauthenticated_inference", ["LLM10:2025", "ASI03"], "CWE-306"),
    ("mcp_unauthenticated", ["MCP07:2025", "MCP09:2025"], "CWE-306"),
    ("provider_key_in_bundle", ["LLM02:2025"], "CWE-798"),
    ("system_prompt_in_bundle", ["LLM07:2025"], "CWE-200"),
    ("verbose_provider_error", ["LLM02:2025"], "CWE-209"),
    ("plaintext_mcp_transport", ["MCP07:2025"], "CWE-319"),
]
STATIC_MAPPING = [
    ("tool_description_injection", ["MCP03:2025", "MCP06:2025", "ASI04"]),
    ("hidden_unicode", ["MCP03:2025", "ASI04"]),
    ("excessive_agency_schema", ["LLM06:2025", "MCP05:2025", "ASI05"]),
    ("toxic_flow", ["ASI02", "MCP10:2025"]),
]


class TestRiskTables:
    def test_each_list_has_ten_ids(self) -> None:
        assert len(LlmRisk) == len(AgenticRisk) == len(McpRisk) == 10
        assert len(AI_RISKS) == 30

    def test_lookup_returns_the_named_risk(self) -> None:
        assert map_ai_risk("LLM01:2025") is LlmRisk.LLM01
        assert map_ai_risk("ASI10") is AgenticRisk.ASI10
        assert map_ai_risk("MCP03:2025") is McpRisk.MCP03
        assert map_ai_risk("LLM01") is None

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
