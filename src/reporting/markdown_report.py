from ..core.remediation import RemediationPlanner
from ..core.risk import get_business_impact
from ..models import Finding, OwaspCategory, ScanSession, Severity
from .base import BaseReporter


class MarkdownReporter(BaseReporter):
    """Generates a Markdown security audit report.

    Structured as:
    1. Executive summary with risk posture
    2. Methodology
    3. Findings overview and OWASP breakdown
    4. Detailed findings with business-impact context
    5. Remediation checklist
    """

    format_name = "markdown"
    file_extension = ".md"

    def generate(self, session: ScanSession) -> str:
        sections = [
            self._title(session),
            self._executive_summary(session),
            self._methodology(session),
            self._findings_overview(session),
            self._findings_by_owasp(session),
            self._detailed_findings(session),
            self._remediation_checklist(session),
            self._footer(),
        ]
        return "\n\n".join(s for s in sections if s)

    def _title(self, session: ScanSession) -> str:
        profile_line = ""
        if session.profile_name:
            profile_line = f"**Profile:** {session.profile_name}  \n"

        return (
            f"# Security Audit Report\n\n"
            f"**Target:** {session.target.base_url}  \n"
            f"{profile_line}"
            f"**Date:** {session.started_at[:10]}  \n"
            f"**Session ID:** {session.session_id}  \n"
            f"**Duration:** {session.duration_seconds:.0f} seconds"
        )

    def _executive_summary(self, session: ScanSession) -> str:
        by_sev = session.findings_by_severity
        total = len(session.all_findings)

        lines = [
            "## Executive Summary\n",
            f"**Risk Posture: {session.risk_posture.value.upper()}**\n",
            f"> {session.risk_posture_text}\n",
        ]

        if session.profile_intro:
            lines.append(f"{session.profile_intro}\n")

        lines.extend([
            f"The assessment identified **{total} finding(s)**",
            f"({session.multi_confirmed_count} confirmed by multiple scanners):\n",
            "| Severity | Count |",
            "|----------|-------|",
        ])

        for sev in Severity:
            count = len(by_sev[sev])
            if count > 0:
                lines.append(f"| {sev.value.capitalize()} | {count} |")

        if session.errors:
            lines.append(
                f"\n> **Note:** {len(session.errors)} scanner error(s) "
                f"occurred during the assessment."
            )

        return "\n".join(lines)

    def _methodology(self, session: ScanSession) -> str:
        scanners = ", ".join(session.scanners_used) or "none"
        scope_domains = ", ".join(session.target.scope.allowed_domains) or "*"

        return (
            "## Methodology\n\n"
            "This assessment was conducted as a **black-box test** — no "
            "source code access was used.\n\n"
            f"- **Scanners:** {scanners}\n"
            f"- **Scope:** {scope_domains}\n"
            f"- **Rate limit:** {session.target.scope.rate_limit_rps} req/s\n"
            f"- **Max requests:** {session.target.scope.max_requests}\n\n"
            "Findings are mapped to the **OWASP Top 10 (2025)** framework."
        )

    def _findings_overview(self, session: ScanSession) -> str:
        if not session.all_findings:
            return "## Findings Overview\n\nNo findings were identified."

        lines = [
            "## Findings Overview\n",
            "| # | Severity | Title | OWASP |",
            "|---|----------|-------|-------|",
        ]
        for i, f in enumerate(session.all_findings, 1):
            owasp = f.owasp_category or "Unmapped"
            lines.append(
                f"| {i} | {f.severity.value.capitalize()} | "
                f"{f.title[:60]} | {owasp[:30]} |"
            )

        return "\n".join(lines)

    def _findings_by_owasp(self, session: ScanSession) -> str:
        grouped = session.findings_by_owasp
        lines = ["## Findings by OWASP Category\n"]

        for cat in OwaspCategory:
            cat_findings = grouped.get(cat.value, [])
            count = len(cat_findings)
            status = f"({count} finding{'s' if count != 1 else ''})"
            lines.append(f"- **{cat.value}** {status}")

        unmapped = grouped.get("Unmapped", [])
        if unmapped:
            lines.append(f"- **Unmapped** ({len(unmapped)} findings)")

        return "\n".join(lines)

    def _detailed_findings(self, session: ScanSession) -> str:
        if not session.all_findings:
            return ""

        lines = ["## Detailed Findings\n"]
        for i, f in enumerate(session.all_findings, 1):
            lines.append(self._render_finding(i, f))

        return "\n\n".join(lines)

    def _render_finding(self, index: int, f: Finding) -> str:
        owasp_label = f.owasp_category or "Unmapped"
        parts = [
            f"### {index}. {f.title}\n",
            "| Field | Value |",
            "|-------|-------|",
            f"| **Severity** | {f.severity.value.capitalize()} |",
            f"| **Confidence** | {f.confidence.value.capitalize()} |",
            f"| **OWASP** | {owasp_label} |",
            f"| **CWE** | {f.cwe_id or 'N/A'} |",
            f"| **URL** | `{f.url}` |",
            f"| **Scanner** | {f.scanner} |",
        ]

        if f.parameter:
            parts.append(f"| **Parameter** | `{f.parameter}` |")

        parts.append(f"\n**Description:** {f.description}")

        # Business impact context
        impact = get_business_impact(f)
        parts.append(
            f"\n**Business Impact:** {impact.headline}  \n"
            f"*Worst case:* {impact.worst_case}"
        )

        if f.evidence:
            parts.append(f"\n**Evidence:**\n```\n{f.evidence}\n```")

        if f.request_example:
            parts.append(
                f"\n**Reproduction:**\n```bash\n{f.request_example}\n```"
            )

        if f.remediation:
            parts.append(f"\n**Remediation:** {f.remediation}")

        if f.references:
            refs = "\n".join(f"- {r}" for r in f.references)
            parts.append(f"\n**References:**\n{refs}")

        return "\n".join(parts)

    def _remediation_checklist(self, session: ScanSession) -> str:
        if not session.remediation_steps:
            return ""

        planner = RemediationPlanner()
        return planner.format_checklist(session.remediation_steps)

    def _footer(self) -> str:
        return (
            "---\n\n"
            "*This report was generated by HARIS. Findings should be "
            "validated by a qualified security professional before "
            "remediation.*"
        )
