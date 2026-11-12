from typing import Any

import pytest
import yaml

from haris.ai_security.owasp_ai import load_mappings
from haris.config.paths import resolve_config_file
from haris.core.engine import ScanEngine
from haris.core.owasp import CLASS_OWASP
from haris.core.scanner import BaseScanner
from haris.core.vuln_class import VULN_CLASSES_FILE
from haris.models import Finding, ScannerResult, Severity, Target

CRYPTO = "A04:2025 - Cryptographic Failures"


class StubScanner(BaseScanner):
    version = "0.0.1"

    def __init__(self, name: str, finding: Finding) -> None:
        super().__init__()
        self.name = name
        self._finding = finding

    def scan(self, target, **kwargs):
        return ScannerResult(
            scanner_name=self.name, raw_output="", findings=[self._finding]
        )

    def parse_results(self, raw_output):
        return [self._finding]


def enrich(scanner_name: str, finding: Finding) -> Finding:
    engine = ScanEngine(
        scanners=[StubScanner(scanner_name, finding)],
        resolver=lambda _host, _port: ["93.184.216.34"],
    )
    return engine.run(Target(base_url="https://example.com")).all_findings[0]


def load_yaml() -> dict[str, Any]:
    with open(resolve_config_file(VULN_CLASSES_FILE), encoding="utf-8") as fh:
        data: dict[str, Any] = yaml.safe_load(fh)
    return data


def ai_mapped_classes() -> set[str]:
    mappings = load_mappings()
    checks = {f"ai_{name}" for name, check in mappings.checks.items() if check.owasp}
    return checks | {"ai_garak", "ai_promptfoo"}


class TestClassCoverage:
    def test_every_class_is_mapped_or_listed_unmapped(self):
        data = load_yaml()
        ids = {c["id"] for c in data["classes"]}
        unmapped = set(data["unmapped"])
        mapped = set(CLASS_OWASP) | ai_mapped_classes()
        both = [i for i in ids if i in mapped and i in unmapped]
        neither = [i for i in ids if i not in mapped and i not in unmapped]
        assert not both, f"mapped and listed unmapped: {sorted(both)}"
        assert not neither, f"neither mapped nor listed unmapped: {sorted(neither)}"
        assert unmapped <= ids, f"unknown unmapped ids: {sorted(unmapped - ids)}"
        assert mapped <= ids, f"unknown mapped ids: {sorted(mapped - ids)}"

    def test_mapped_cwe_matches_class_primary_cwe(self):
        primary = {c["id"]: c["primary_cwe"] for c in load_yaml()["classes"]}
        mismatched = {
            cls: (mapping.typical_cwes[0], primary[cls])
            for cls, mapping in CLASS_OWASP.items()
            if mapping.typical_cwes[0] != primary[cls]
        }
        assert not mismatched, f"mapping CWE differs from primary_cwe: {mismatched}"


class TestEnrichmentOrder:
    @pytest.mark.parametrize("tags", [[], ["xss"]])
    def test_class_mapping_wins_for_wapiti_cleartext_password(self, tags):
        finding = Finding(
            title="Cleartext Submission of Password: form posts over http",
            description="",
            severity=Severity.MEDIUM,
            tags=tags,
        )
        result = enrich("wapiti", finding)
        assert result.vuln_class == "cleartext_password_submission"
        assert result.owasp_category == CRYPTO
        assert result.cwe_id == "CWE-319"

    def test_unclassified_finding_still_maps_from_tag(self):
        finding = Finding(
            title="Something scanner specific",
            description="",
            severity=Severity.HIGH,
            tags=["sql_injection"],
        )
        result = enrich("mock", finding)
        assert result.vuln_class.startswith("unclassified:")
        assert result.owasp_category == "A05:2025 - Injection"
        assert result.cwe_id == "CWE-89"

    def test_existing_cwe_is_kept(self):
        finding = Finding(
            title="Cleartext Submission of Password: form",
            description="",
            severity=Severity.MEDIUM,
            cwe_id="CWE-200",
        )
        assert enrich("wapiti", finding).cwe_id == "CWE-200"
