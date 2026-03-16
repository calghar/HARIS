"""Prompt builders for report Q&A — delegates to Jinja2 templates."""

from ..models import Finding, ScanSession
from .template_loader import render_template

_AUDIENCE_INSTRUCTIONS = {
    "executive": (
        "Write a 3-5 paragraph executive summary for a non-technical "
        "audience (C-suite, product managers).  Focus on business "
        "impact, risk level, and recommended next steps.  Avoid "
        "jargon; explain technical concepts in plain language."
    ),
    "technical": (
        "Write a technical summary for the security team.  Cover "
        "the most critical findings, attack surface observations, "
        "and prioritised remediation.  Reference specific finding "
        "IDs and CWEs."
    ),
    "developer": (
        "Write a developer-oriented summary focusing on which "
        "code areas or configurations need fixing.  Group by "
        "effort level (quick wins vs. larger changes).  Include "
        "concrete technical recommendations."
    ),
}

_FORMAT_INSTRUCTIONS = {
    "jira": (
        "Generate a remediation plan formatted as Jira epic/story "
        "descriptions.  For each remediation step, produce:\n"
        "- Epic title\n"
        "- Description with acceptance criteria\n"
        "- Priority (Critical/High/Medium/Low)\n"
        "- Estimated effort\n"
        "- Related finding IDs"
    ),
    "markdown": (
        "Generate a remediation plan as a Markdown document with:\n"
        "- Phase 1: Quick wins (< 1 hour each)\n"
        "- Phase 2: Moderate effort (1-8 hours)\n"
        "- Phase 3: Significant changes (> 8 hours)\n"
        "For each item, include the fix, why it matters, and "
        "which findings it addresses."
    ),
    "email": (
        "Draft a professional email to the product owner "
        "summarising the risk posture and top remediation "
        "priorities.  Keep it under 500 words.  Be specific "
        "about what needs action and what the business impact is."
    ),
}


class PromptBuilder:
    """Builds prompts from structured scan data.

    Each method returns a (system_prompt, user_prompt) tuple.
    """

    @staticmethod
    def system_prompt() -> str:
        return render_template("qa/system.j2")

    @staticmethod
    def _format_finding_context(finding: Finding) -> str:
        parts = [
            f"- **{finding.finding_id}**: {finding.title}",
            f"  Severity: {finding.severity.value} | "
            f"Confidence: {finding.confidence.value}",
            f"  OWASP: {finding.owasp_category or 'Unmapped'}",
        ]
        if finding.url:
            parts.append(f"  URL: {finding.url}")
        if finding.description:
            parts.append(f"  Description: {finding.description[:300]}")
        if finding.remediation:
            parts.append(f"  Remediation: {finding.remediation[:200]}")
        if finding.evidence:
            parts.append(f"  Evidence: {finding.evidence[:150]}")
        return "\n".join(parts)

    @classmethod
    def _format_session_context(cls, session: ScanSession) -> str:
        lines = [
            "## Report Context",
            f"- Target: {session.target.base_url}",
            f"- Scan date: {session.started_at[:10]}",
            f"- Profile: {session.profile_name or 'custom'}",
            f"- Risk posture: {session.risk_posture.value.upper()}",
            f"- Total findings: {len(session.all_findings)}",
            f"- Scanners used: {', '.join(session.scanners_used)}",
            "",
            "## Findings",
        ]
        for f in session.all_findings:
            lines.append(cls._format_finding_context(f))
            lines.append("")

        if session.remediation_steps:
            lines.append("## Remediation Steps")
            for step in session.remediation_steps:
                lines.append(
                    f"- [{step.effort.value}] {step.title} "
                    f"({step.finding_count} findings, "
                    f"impact: {step.impact.value})"
                )
            lines.append("")

        return "\n".join(lines)

    @classmethod
    def _format_selective_context(
        cls,
        session: ScanSession,
        relevant_findings: list[Finding],
    ) -> str:
        """Build context with full details for relevant findings only.

        Non-relevant findings are summarised as one-liners to save tokens
        while still giving the LLM awareness of the full scan scope.
        """
        relevant_ids = {f.finding_id for f in relevant_findings}
        total = len(session.all_findings)
        shown = len(relevant_findings)

        lines = [
            "## Report Context",
            f"- Target: {session.target.base_url}",
            f"- Scan date: {session.started_at[:10]}",
            f"- Profile: {session.profile_name or 'custom'}",
            f"- Risk posture: {session.risk_posture.value.upper()}",
            f"- Total findings: {total}",
            f"- Scanners: {', '.join(session.scanners_used)}",
            "",
            f"## Relevant Findings ({shown} of {total})",
        ]
        for f in relevant_findings:
            lines.append(cls._format_finding_context(f))
            lines.append("")

        # One-line summaries for remaining findings
        others = [
            f
            for f in session.all_findings
            if f.finding_id not in relevant_ids
        ]
        if others:
            lines.append("## Other Findings (summary only)")
            for f in others:
                lines.append(
                    f"- [{f.severity.value.upper()}] {f.title}"
                )
            lines.append("")

        return "\n".join(lines)

    @classmethod
    def summarize_report(
        cls,
        session: ScanSession,
        audience: str = "executive",
    ) -> tuple[str, str]:
        context = cls._format_session_context(session)
        instruction = _AUDIENCE_INSTRUCTIONS.get(
            audience, _AUDIENCE_INSTRUCTIONS["executive"]
        )
        prompt = render_template(
            "qa/summarize_report.j2",
            context=context,
            instruction=instruction,
        )
        return cls.system_prompt(), prompt

    @classmethod
    def explain_finding(
        cls,
        finding: Finding,
        session: ScanSession,
        audience: str = "executive",
    ) -> tuple[str, str]:
        context = cls._format_session_context(session)
        finding_detail = cls._format_finding_context(finding)
        prompt = render_template(
            "qa/explain_finding.j2",
            context=context,
            finding_detail=finding_detail,
            audience=audience,
        )
        return cls.system_prompt(), prompt

    @classmethod
    def propose_remediation_plan(
        cls,
        session: ScanSession,
        format: str = "jira",
    ) -> tuple[str, str]:
        context = cls._format_session_context(session)
        instruction = _FORMAT_INSTRUCTIONS.get(
            format, _FORMAT_INSTRUCTIONS["markdown"]
        )
        prompt = render_template(
            "qa/remediation_plan.j2",
            context=context,
            instruction=instruction,
        )
        return cls.system_prompt(), prompt

    @classmethod
    def filter_and_explain(
        cls,
        session: ScanSession,
        filter_query: str,
    ) -> tuple[str, str]:
        context = cls._format_session_context(session)
        prompt = render_template(
            "qa/filter_and_explain.j2",
            context=context,
            filter_query=filter_query,
        )
        return cls.system_prompt(), prompt

    @classmethod
    def generate_test_cases(
        cls,
        session: ScanSession,
        framework: str = "generic",
    ) -> tuple[str, str]:
        context = cls._format_session_context(session)
        prompt = render_template(
            "qa/generate_test_cases.j2",
            context=context,
            framework=framework,
        )
        return cls.system_prompt(), prompt

    @classmethod
    def suggest_mitigations(
        cls,
        session: ScanSession,
        stack: str = "generic web",
    ) -> tuple[str, str]:
        context = cls._format_session_context(session)
        prompt = render_template(
            "qa/suggest_mitigations.j2",
            context=context,
            stack=stack,
        )
        return cls.system_prompt(), prompt

    @classmethod
    def freeform_question(
        cls,
        session: ScanSession,
        question: str,
    ) -> tuple[str, str]:
        context = cls._format_session_context(session)
        prompt = render_template(
            "qa/freeform_question.j2",
            context=context,
            question=question,
        )
        return cls.system_prompt(), prompt
