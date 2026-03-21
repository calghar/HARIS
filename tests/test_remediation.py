"""Tests for remediation planning."""

from src.core.remediation import RemediationPlanner
from src.models import Effort, Finding, Severity


class TestRemediationPlanner:
    def test_empty_findings(self):
        planner = RemediationPlanner()
        steps = planner.plan([])
        assert steps == []

    def test_groups_similar_remediation(self):
        planner = RemediationPlanner()
        findings = [
            Finding(
                title="Missing HSTS",
                description="",
                severity=Severity.MEDIUM,
                remediation=(
                    "Add the header: Strict-Transport-Security: max-age=31536000"
                ),
            ),
            Finding(
                title="Missing HSTS on /api",
                description="",
                severity=Severity.MEDIUM,
                remediation=(
                    "Add the header: Strict-Transport-Security: max-age=31536000"
                ),
            ),
        ]
        steps = planner.plan(findings)
        assert len(steps) == 1
        assert steps[0].finding_count == 2

    def test_effort_estimation_quick_win(self):
        planner = RemediationPlanner()
        findings = [
            Finding(
                title="Missing header",
                description="",
                severity=Severity.LOW,
                remediation="Add header: X-Content-Type-Options: nosniff",
            ),
        ]
        steps = planner.plan(findings)
        assert steps[0].effort == Effort.QUICK_WIN

    def test_effort_estimation_moderate(self):
        planner = RemediationPlanner()
        findings = [
            Finding(
                title="XSS",
                description="",
                severity=Severity.HIGH,
                remediation="Sanitise user input and encode output in templates.",
            ),
        ]
        steps = planner.plan(findings)
        assert steps[0].effort == Effort.MODERATE

    def test_sorted_by_priority(self):
        planner = RemediationPlanner()
        findings = [
            Finding(
                title="Low issue",
                description="",
                severity=Severity.LOW,
                remediation="Remove the X-Powered-By header.",
            ),
            Finding(
                title="Critical issue",
                description="",
                severity=Severity.CRITICAL,
                remediation="Sanitise all database queries to prevent SQL injection.",
            ),
        ]
        steps = planner.plan(findings)
        # Critical should come first
        assert steps[0].impact == Severity.CRITICAL

    def test_format_checklist(self):
        planner = RemediationPlanner()
        findings = [
            Finding(
                title="Missing HSTS",
                description="",
                severity=Severity.MEDIUM,
                remediation=(
                    "Add the header: Strict-Transport-Security: max-age=31536000"
                ),
            ),
        ]
        steps = planner.plan(findings)
        checklist = planner.format_checklist(steps)
        assert "Quick Wins" in checklist
        assert "- [ ]" in checklist

    def test_format_checklist_empty(self):
        planner = RemediationPlanner()
        result = planner.format_checklist([])
        assert "No remediation" in result
