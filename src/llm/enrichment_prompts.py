from ..models import Finding, Target
from ..models.enrichment import TriageContext
from .template_loader import render_template


class EnrichmentPromptBuilder:
    """Builds prompts for finding enrichment, correlation, and triage."""

    @staticmethod
    def system() -> str:
        return render_template("enrichment/system.j2")

    @classmethod
    def enrich_finding(
        cls,
        finding: Finding,
        target: Target,
        sibling_titles: list[str],
    ) -> tuple[str, str]:
        prompt = render_template(
            "enrichment/enrich_finding.j2",
            finding=finding,
            target=target,
            sibling_titles=sibling_titles,
        )
        return cls.system(), prompt

    @classmethod
    def identify_attack_chains(
        cls,
        findings: list[Finding],
    ) -> tuple[str, str]:
        prompt = render_template(
            "enrichment/identify_attack_chains.j2",
            findings=findings,
        )
        return cls.system(), prompt

    @classmethod
    def assess_false_positives(
        cls,
        findings: list[Finding],
    ) -> tuple[str, str]:
        prompt = render_template(
            "enrichment/assess_false_positives.j2",
            findings=findings,
        )
        return cls.system(), prompt

    @classmethod
    def suggest_variants(
        cls,
        finding: Finding,
        target: Target,
    ) -> tuple[str, str]:
        prompt = render_template(
            "enrichment/suggest_variants.j2",
            finding=finding,
            target=target,
        )
        return cls.system(), prompt

    @classmethod
    def triage_findings(
        cls,
        findings: list[Finding],
        context: TriageContext,
    ) -> tuple[str, str]:
        ctx_parts = []
        if context.industry:
            ctx_parts.append(f"Industry: {context.industry}")
        if context.data_sensitivity:
            ctx_parts.append(f"Data sensitivity: {context.data_sensitivity}")
        if context.compliance_frameworks:
            ctx_parts.append(f"Compliance: {', '.join(context.compliance_frameworks)}")
        ctx_text = (
            "\n".join(ctx_parts) if ctx_parts else "No specific context provided."
        )

        prompt = render_template(
            "enrichment/triage_findings.j2",
            findings=findings,
            ctx_text=ctx_text,
        )
        return cls.system(), prompt
