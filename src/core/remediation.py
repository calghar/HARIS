from ..models import Effort, Finding, RemediationStep, Severity

# Mapping from remediation keywords to effort estimates
_EFFORT_HINTS: dict[str, Effort] = {
    "add header": Effort.QUICK_WIN,
    "add the header": Effort.QUICK_WIN,
    "set the": Effort.QUICK_WIN,
    "remove the": Effort.QUICK_WIN,
    "remove version": Effort.QUICK_WIN,
    "suppress version": Effort.QUICK_WIN,
    "disable": Effort.QUICK_WIN,
    "enable https": Effort.MODERATE,
    "configure": Effort.MODERATE,
    "restrict access": Effort.MODERATE,
    "implement": Effort.MODERATE,
    "sanitise": Effort.MODERATE,
    "sanitize": Effort.MODERATE,
    "validate": Effort.MODERATE,
    "update": Effort.MODERATE,
    "renew": Effort.MODERATE,
    "redesign": Effort.SIGNIFICANT,
    "refactor": Effort.SIGNIFICANT,
    "migrate": Effort.SIGNIFICANT,
}


class RemediationPlanner:
    """Generate a prioritised remediation checklist from findings."""

    def plan(self, findings: list[Finding]) -> list[RemediationStep]:
        """Create an ordered list of remediation steps.

        Findings with similar remediation text are grouped into a single
        step.  Steps are sorted by ``priority_score`` (descending).
        """
        buckets: dict[str, list[Finding]] = {}

        for f in findings:
            if not f.remediation:
                continue
            # Group by normalised remediation text (first 80 chars)
            key = f.remediation.strip()[:80].lower()
            buckets.setdefault(key, []).append(f)

        steps: list[RemediationStep] = []
        for _key, group in buckets.items():
            representative = group[0]
            highest_sev = min(group, key=lambda f: f.severity.sort_key).severity
            effort = self._estimate_effort(representative.remediation)

            step = RemediationStep(
                title=self._make_title(representative.remediation),
                description=representative.remediation,
                effort=effort,
                impact=highest_sev,
                finding_ids=[f.finding_id for f in group],
                finding_count=len(group),
                category=representative.owasp_category or "General",
            )
            steps.append(step)

        steps.sort(key=lambda s: s.priority_score, reverse=True)
        return steps

    def format_checklist(self, steps: list[RemediationStep]) -> str:
        """Render remediation steps as a Markdown checklist."""
        if not steps:
            return "No remediation steps required."

        sections: dict[Effort, list[RemediationStep]] = {
            Effort.QUICK_WIN: [],
            Effort.MODERATE: [],
            Effort.SIGNIFICANT: [],
        }
        for s in steps:
            sections[s.effort].append(s)

        lines = ["## Remediation Checklist\n"]
        labels = {
            Effort.QUICK_WIN: "Quick Wins (< 1 hour each)",
            Effort.MODERATE: "Moderate Effort (1-8 hours each)",
            Effort.SIGNIFICANT: "Significant Changes (> 8 hours each)",
        }

        for effort, label in labels.items():
            group = sections[effort]
            if not group:
                continue
            lines.append(f"### {label}\n")
            for s in group:
                sev = s.impact.value.upper()
                lines.append(
                    f"- [ ] **[{sev}]** {s.title} "
                    f"({s.finding_count} finding{'s' if s.finding_count != 1 else ''})"
                )
                lines.append(f"  - {s.description}")
            lines.append("")

        return "\n".join(lines)

    @staticmethod
    def _estimate_effort(remediation_text: str) -> Effort:
        text_lower = remediation_text.lower()
        for hint, effort in _EFFORT_HINTS.items():
            if hint in text_lower:
                return effort
        return Effort.MODERATE

    @staticmethod
    def _make_title(remediation_text: str) -> str:
        """Extract a short title from remediation text."""
        first_sentence = remediation_text.split(".")[0].strip()
        if len(first_sentence) > 60:
            first_sentence = first_sentence[:57] + "..."
        return first_sentence


# Re-export Severity so existing imports from this module continue to work
__all__ = ["Effort", "Finding", "RemediationPlanner", "RemediationStep", "Severity"]
