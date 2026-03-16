"""Tests for OWASP Top 10 (2025) mapping utilities."""

from src.core.owasp import all_categories, map_cwe_to_owasp, map_to_owasp
from src.models import OwaspCategory


class TestMapToOwasp:
    def test_known_keyword(self):
        mapping = map_to_owasp("sql_injection")
        assert mapping is not None
        assert mapping.category == OwaspCategory.A05_INJECTION

    def test_normalisation(self):
        mapping = map_to_owasp("SQL Injection")
        assert mapping is not None
        assert mapping.category == OwaspCategory.A05_INJECTION

    def test_xss(self):
        mapping = map_to_owasp("xss")
        assert mapping is not None
        assert mapping.category == OwaspCategory.A05_INJECTION

    def test_missing_hsts(self):
        mapping = map_to_owasp("missing_hsts")
        assert mapping is not None
        assert mapping.category == OwaspCategory.A04_CRYPTOGRAPHIC_FAILURES

    def test_unknown_keyword(self):
        assert map_to_owasp("nonexistent_vuln") is None

    def test_ssrf_maps_to_broken_access_control(self):
        mapping = map_to_owasp("ssrf")
        assert mapping is not None
        assert mapping.category == OwaspCategory.A01_BROKEN_ACCESS_CONTROL

    def test_supply_chain_keyword(self):
        mapping = map_to_owasp("supply_chain")
        assert mapping is not None
        assert mapping.category == OwaspCategory.A03_SUPPLY_CHAIN_FAILURES

    def test_exceptional_conditions_keywords(self):
        mapping = map_to_owasp("fail_open")
        assert mapping is not None
        assert mapping.category == OwaspCategory.A10_EXCEPTIONAL_CONDITIONS

    def test_improper_error_handling(self):
        mapping = map_to_owasp("improper_error_handling")
        assert mapping is not None
        assert mapping.category == OwaspCategory.A10_EXCEPTIONAL_CONDITIONS


class TestMapCweToOwasp:
    def test_cwe_89_sql_injection(self):
        mapping = map_cwe_to_owasp("CWE-89")
        assert mapping is not None
        assert mapping.category == OwaspCategory.A05_INJECTION

    def test_cwe_without_prefix(self):
        mapping = map_cwe_to_owasp("89")
        assert mapping is not None

    def test_unknown_cwe(self):
        assert map_cwe_to_owasp("CWE-99999") is None


class TestAllCategories:
    def test_returns_10_categories(self):
        cats = all_categories()
        assert len(cats) == 10

    def test_order(self):
        cats = all_categories()
        assert cats[0] == OwaspCategory.A01_BROKEN_ACCESS_CONTROL
        assert cats[9] == OwaspCategory.A10_EXCEPTIONAL_CONDITIONS
