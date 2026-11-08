from collections import Counter

from ..core.risk import get_business_impact
from ..diff import LoadedReport
from ..models import Effort, Finding, OwaspCategory, ScanSession, ScanState, Severity
from .base import BaseReporter
from .escape import md_code, md_fence, md_text
from .findings import inactive_reason, split_findings

UNFINISHED = {ScanState.INCOMPLETE, ScanState.FAILED, ScanState.CANCELLED}
EFFORT_LABELS = {
    Effort.QUICK_WIN: "Quick Wins (< 1 hour each)",
    Effort.MODERATE: "Moderate Effort (1-8 hours each)",
    Effort.SIGNIFICANT: "Significant Changes (> 8 hours each)",
}


class MarkdownReporter(BaseReporter):
    """Markdown security audit report with every target-controlled value escaped.

    Active findings fill the body; refuted and suppressed ones go to an appendix.
    ``for_html`` leaves code blocks raw because the HTML converter escapes them.
    """

    format_name = "markdown"
    file_extension = ".md"

    def __init__(
        self, baseline: LoadedReport | None = None, *, for_html: bool = False
    ) -> None:
        super().__init__(baseline)
        self._angles = not for_html

    def generate(self, session: ScanSession) -> str:
        active, inactive = split_findings(session)
        sections = [
            self._title(session),
            self._executive_summary(session, active, len(inactive)),
            self._methodology(session),
            self._findings_overview(active),
            self._findings_by_owasp(active),
            self._detailed_findings(active),
            self._remediation_checklist(session),
            self._appendix(inactive),
            self._footer(),
        ]
        return "\n\n".join(s for s in sections if s)

    def _title(self, session: ScanSession) -> str:
        profile = (
            f"**Profile:** {md_text(session.profile_name)}  \n"
            if session.profile_name
            else ""
        )
        return (
            "# Security Audit Report\n\n"
            f"**Target:** {md_text(session.target.base_url)}  \n"
            f"{profile}"
            f"**Date:** {md_text(session.started_at[:10])}  \n"
            f"**Session ID:** {md_text(session.session_id)}  \n"
            f"**Duration:** {session.duration_seconds:.0f} seconds"
        )

    def _executive_summary(
        self, session: ScanSession, active: list[Finding], inactive: int
    ) -> str:
        counts = Counter(f.severity for f in active)
        lines = [
            "## Executive Summary\n",
            f"**Risk Posture: {session.risk_posture.value.upper()}**\n",
            f"> {md_text(session.risk_posture_text)}\n",
        ]
        if session.profile_intro:
            lines.append(f"{md_text(session.profile_intro)}\n")
        lines.append(
            f"The assessment identified **{len(active)} finding(s)** "
            f"({session.multi_confirmed_count} confirmed by multiple scanners; "
            f"{inactive} refuted or suppressed, listed in the appendix):\n"
        )
        lines += ["| Severity | Count |", "|----------|-------|"]
        lines += [
            f"| {sev.value.capitalize()} | {counts[sev]} |"
            for sev in Severity
            if counts[sev]
        ]
        if session.scan_state in UNFINISHED:
            failed = [n for n, s in session.scanner_status.items() if s != "completed"]
            detail = f"; scanners not completed: {', '.join(failed)}" if failed else ""
            lines.append(
                f"\n> **Scan {session.scan_state.value}**{md_text(detail)}. "
                "Absent findings do not mean the target is clean."
            )
        if session.errors:
            lines.append(
                f"\n> **Note:** {len(session.errors)} scanner error(s) "
                "occurred during the assessment."
            )
        return "\n".join(lines)

    def _methodology(self, session: ScanSession) -> str:
        scanners = ", ".join(session.scanners_used) or "none"
        scope = ", ".join(session.target.scope.allowed_domains) or "*"
        return (
            "## Methodology\n\n"
            "This assessment was conducted as a **black-box test**; no "
            "source code access was used.\n\n"
            f"- **Scanners:** {md_text(scanners)}\n"
            f"- **Scope:** {md_text(scope)}\n"
            f"- **Rate limit:** {session.target.scope.rate_limit_rps} req/s\n"
            f"- **Max requests:** {session.target.scope.max_requests}\n\n"
            "Findings are mapped to the **OWASP Top 10 (2025)** framework."
        )

    def _findings_overview(self, active: list[Finding]) -> str:
        if not active:
            return "## Findings Overview\n\nNo findings were identified."
        lines = [
            "## Findings Overview\n",
            "| # | Severity | Verification | Title | OWASP |",
            "|---|----------|--------------|-------|-------|",
        ]
        for i, f in enumerate(active, 1):
            owasp = md_text((f.owasp_category or "Unmapped")[:30])
            lines.append(
                f"| {i} | {f.severity.value.capitalize()} "
                f"| {f.verification.tier.value} | {md_text(f.title[:60])} | {owasp} |"
            )
        return "\n".join(lines)

    def _findings_by_owasp(self, active: list[Finding]) -> str:
        counts = Counter(f.owasp_category or "Unmapped" for f in active)
        lines = ["## Findings by OWASP Category\n"]
        for cat in OwaspCategory:
            n = counts.pop(cat.value, 0)
            lines.append(f"- **{cat.value}** ({n} finding{'s' if n != 1 else ''})")
        if counts:
            lines.append(f"- **Unmapped** ({sum(counts.values())} findings)")
        return "\n".join(lines)

    def _detailed_findings(self, active: list[Finding]) -> str:
        if not active:
            return ""
        parts = ["## Detailed Findings\n"]
        parts += [self._render_finding(i, f) for i, f in enumerate(active, 1)]
        return "\n\n".join(parts)

    def _render_finding(self, index: int, f: Finding) -> str:
        v = f.verification
        parts = [
            f"### {index}. {md_text(f.title)}\n",
            "| Field | Value |",
            "|-------|-------|",
            f"| **Severity** | {f.severity.value.capitalize()} |",
            f"| **Confidence** | {f.confidence.value.capitalize()} "
            f"({f.confidence_score:.2f}) |",
            f"| **Verification** | {v.tier.value} ({v.method.value}) |",
            f"| **OWASP** | {md_text(f.owasp_category or 'Unmapped')} |",
            f"| **CWE** | {md_text(f.cwe_id or 'N/A')} |",
            f"| **URL** | {md_code(f.url, angles=self._angles)} |",
            f"| **Scanner** | {md_text(f.scanner)} |",
        ]
        if f.parameter:
            parts.append(
                f"| **Parameter** | {md_code(f.parameter, angles=self._angles)} |"
            )
        parts.append(f"\n**Description:** {md_text(f.description)}")
        impact = get_business_impact(f)
        parts.append(
            f"\n**Business Impact:** {impact.headline}  \n"
            f"*Worst case:* {impact.worst_case}"
        )
        if f.evidence:
            parts.append(
                f"\n**Evidence:**\n{md_fence(f.evidence, angles=self._angles)}"
            )
        if f.request_example:
            parts.append(
                f"\n**Reproduction:**\n"
                f"{md_fence(f.request_example, angles=self._angles)}"
            )
        if f.remediation:
            parts.append(f"\n**Remediation:** {md_text(f.remediation)}")
        if f.references:
            refs = "\n".join(
                f"- {md_code(r, angles=self._angles)}" for r in f.references
            )
            parts.append(f"\n**References:**\n\n{refs}")
        return "\n".join(parts)

    def _remediation_checklist(self, session: ScanSession) -> str:
        if not session.remediation_steps:
            return ""
        lines = ["## Remediation Checklist\n"]
        for effort, label in EFFORT_LABELS.items():
            steps = [s for s in session.remediation_steps if s.effort == effort]
            if not steps:
                continue
            lines.append(f"### {label}\n")
            for s in steps:
                n = s.finding_count
                lines.append(
                    f"- [ ] **[{s.impact.value.upper()}]** {md_text(s.title)} "
                    f"({n} finding{'s' if n != 1 else ''})"
                )
                lines.append(f"  - {md_text(s.description)}")
            lines.append("")
        return "\n".join(lines)

    def _appendix(self, inactive: list[Finding]) -> str:
        if not inactive:
            return ""
        lines = [
            "## Appendix: Refuted and Suppressed Findings\n",
            "These findings are not counted above.\n",
            "| # | Severity | Title | Status | URL |",
            "|---|----------|-------|--------|-----|",
        ]
        lines += [
            f"| {i} | {f.severity.value.capitalize()} | {md_text(f.title[:60])} "
            f"| {md_text(inactive_reason(f))} | {md_code(f.url, angles=self._angles)} |"
            for i, f in enumerate(inactive, 1)
        ]
        return "\n".join(lines)

    def _footer(self) -> str:
        return (
            "---\n\n"
            "*This report was generated by HARIS. Findings should be "
            "validated by a qualified security professional before "
            "remediation.*"
        )
