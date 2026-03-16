"""Tests for the Finding model."""

from src.models import Confidence, Finding, Severity


class TestSeverity:
    def test_sort_order(self):
        severities = [
            Severity.LOW, Severity.CRITICAL, Severity.MEDIUM,
            Severity.INFO, Severity.HIGH,
        ]
        sorted_sevs = sorted(severities, key=lambda s: s.sort_key)
        assert sorted_sevs == [
            Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM,
            Severity.LOW, Severity.INFO,
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
