"""Tests for the Finding model."""

import json
from pathlib import Path

import pytest

from haris.models import (
    Confidence,
    Finding,
    Severity,
    Suppression,
    VerificationTier,
)

REPORT_0_6_2 = Path(__file__).parent / "fixtures" / "report_0_6_2.json"


class TestSeverity:
    def test_sort_order(self):
        severities = [
            Severity.LOW,
            Severity.CRITICAL,
            Severity.MEDIUM,
            Severity.INFO,
            Severity.HIGH,
        ]
        sorted_sevs = sorted(severities, key=lambda s: s.sort_key)
        assert sorted_sevs == [
            Severity.CRITICAL,
            Severity.HIGH,
            Severity.MEDIUM,
            Severity.LOW,
            Severity.INFO,
        ]


class TestFinding:
    def test_to_dict(self):
        f = Finding(
            title="Test XSS",
            description="Reflected XSS found",
            severity=Severity.HIGH,
            confidence=Confidence.CONFIRMED,
            url="https://example.com/search?q=test",
            parameter="q",
            scanner="wapiti",
        )
        d = f.to_dict()
        assert d["title"] == "Test XSS"
        assert d["severity"] == "high"
        assert d["confidence"] == "confirmed"
        assert d["parameter"] == "q"
        assert d["scanner"] == "wapiti"
        assert "finding_id" in d

    def test_from_dict(self):
        data = {
            "title": "Missing HSTS",
            "description": "No HSTS header",
            "severity": "medium",
            "confidence": "firm",
            "url": "https://example.com",
        }
        f = Finding.from_dict(data)
        assert f.title == "Missing HSTS"
        assert f.severity == Severity.MEDIUM
        assert f.confidence == Confidence.FIRM

    def test_roundtrip(self):
        original = Finding(
            title="SQL Injection",
            description="Error-based SQLi in login form",
            severity=Severity.CRITICAL,
            confidence=Confidence.CONFIRMED,
            url="https://example.com/login",
            parameter="username",
            method="POST",
            scanner="wapiti",
            tags=["sql_injection"],
        )
        d = original.to_dict()
        restored = Finding.from_dict(d)
        assert restored.title == original.title
        assert restored.severity == original.severity
        assert restored.url == original.url

    def test_unique_finding_id(self):
        f1 = Finding(title="A", description="", severity=Severity.INFO)
        f2 = Finding(title="B", description="", severity=Severity.INFO)
        assert f1.finding_id != f2.finding_id


class TestBackwardCompatibility:
    def test_report_from_0_6_2_loads_unchanged(self):
        """A report written by 0.6.2 loads; every old key keeps its value."""
        report = json.loads(REPORT_0_6_2.read_text())
        assert report["findings"], "fixture must hold findings"

        for old in report["findings"]:
            loaded = Finding.from_dict(old)
            assert loaded.finding_id == old["finding_id"]
            new = loaded.to_dict()
            assert {k: new[k] for k in old} == old
            assert loaded.verification.tier == VerificationTier.UNVERIFIED
            assert loaded.suppression is None
            assert loaded.fingerprint == ""

    def test_scanner_style_construction_still_works(self):
        f = Finding(
            title="t",
            description="d",
            severity=Severity.LOW,
            confidence=Confidence.CONFIRMED,
        )
        assert f.confidence == Confidence.CONFIRMED
        assert f.finding_id == f.observation_id
        assert f.is_active

    def test_new_fields_round_trip(self):
        f = Finding(title="t", description="d", severity=Severity.LOW)
        f.verification.advance(VerificationTier.REPLAY_VERIFIED)
        f.suppression = Suppression(reason="r", author="a", expires="2027-01-01")
        restored = Finding.from_dict(json.loads(json.dumps(f.to_dict())))
        assert restored.verification.tier == VerificationTier.REPLAY_VERIFIED
        assert restored.suppression == f.suppression
        assert not restored.is_active


class TestConfidenceScore:
    @pytest.mark.parametrize(
        ("score", "expected"),
        [
            (0.95, Confidence.CONFIRMED),
            (0.9, Confidence.CONFIRMED),
            (0.89, Confidence.FIRM),
            (0.6, Confidence.FIRM),
            (0.59, Confidence.TENTATIVE),
        ],
    )
    def test_enum_derived_from_score(self, score, expected):
        f = Finding(
            title="t", description="d", severity=Severity.LOW, confidence_score=score
        )
        assert f.confidence == expected

    def test_explicit_enum_is_kept_when_only_enum_given(self):
        f = Finding(
            title="t",
            description="d",
            severity=Severity.LOW,
            confidence=Confidence.FIRM,
        )
        assert f.confidence == Confidence.FIRM
        assert "confidence_score" not in f.model_fields_set

    def test_score_out_of_range_rejected(self):
        with pytest.raises(ValueError, match="confidence_score"):
            Finding(
                title="t", description="d", severity=Severity.LOW, confidence_score=1.2
            )


class TestTierTransitions:
    @pytest.mark.parametrize(
        ("start", "target", "allowed"),
        [
            (VerificationTier.UNVERIFIED, VerificationTier.REPLAY_VERIFIED, True),
            (VerificationTier.UNVERIFIED, VerificationTier.REFUTED, True),
            (VerificationTier.UNVERIFIED, VerificationTier.EXPLOIT_VALIDATED, True),
            (
                VerificationTier.REPLAY_VERIFIED,
                VerificationTier.EXPLOIT_VALIDATED,
                True,
            ),
            (VerificationTier.REPLAY_VERIFIED, VerificationTier.REFUTED, False),
            (VerificationTier.REFUTED, VerificationTier.REPLAY_VERIFIED, False),
            (VerificationTier.EXPLOIT_VALIDATED, VerificationTier.UNVERIFIED, False),
        ],
    )
    def test_only_documented_transitions(self, start, target, allowed):
        f = Finding(title="t", description="d", severity=Severity.LOW)
        f.verification.tier = start
        if allowed:
            f.verification.advance(target)
            assert f.verification.tier == target
        else:
            with pytest.raises(ValueError, match="not allowed"):
                f.verification.advance(target)
