from ..models import BusinessImpact, Finding, OwaspCategory, RiskPosture, Severity

# Map OWASP 2025 categories to business-language impact descriptions.
# These are intentionally written for a non-technical audience.
_BUSINESS_IMPACT: dict[str, BusinessImpact] = {
    OwaspCategory.A01_BROKEN_ACCESS_CONTROL.value: BusinessImpact(
        headline="Unauthorised users may access restricted data or functions",
        explanation=(
            "Access controls determine who can see and do what in your "
            "application.  When these are broken, an attacker can view "
            "other users' data, modify records, or perform actions they "
            "shouldn't be allowed to.  Server-Side Request Forgery (SSRF) "
            "is also included here — an attacker can trick your server into "
            "fetching internal resources that should never be externally accessible."
        ),
        who_is_affected="All users whose data or accounts could be accessed",
        worst_case=(
            "Full data breach, cloud credential theft, "
            "regulatory fines, loss of customer trust"
        ),
    ),
    OwaspCategory.A02_SECURITY_MISCONFIGURATION.value: BusinessImpact(
        headline="The server or application is configured insecurely",
        explanation=(
            "Default settings, exposed admin panels, verbose error "
            "messages, or unnecessary services give attackers a roadmap "
            "of your infrastructure and easy entry points."
        ),
        who_is_affected="The organisation — infrastructure details are exposed",
        worst_case=(
            "Server compromise via known default credentials or exposed admin tools"
        ),
    ),
    OwaspCategory.A03_SUPPLY_CHAIN_FAILURES.value: BusinessImpact(
        headline="Third-party code in the software supply chain may be compromised",
        explanation=(
            "The application depends on external libraries, packages, or build "
            "tools that may contain known vulnerabilities or have been tampered "
            "with.  Attackers increasingly target supply chains because a single "
            "compromised package can affect thousands of downstream applications."
        ),
        who_is_affected=(
            "All users — the compromised code runs with the "
            "same privileges as the application"
        ),
        worst_case="Persistent backdoor via poisoned dependency, mass exploitation",
    ),
    OwaspCategory.A04_CRYPTOGRAPHIC_FAILURES.value: BusinessImpact(
        headline="Sensitive data may be exposed in transit or at rest",
        explanation=(
            "Weak or missing encryption means passwords, payment details, "
            "or personal information can be intercepted by anyone on the "
            "same network (e.g. public Wi-Fi)."
        ),
        who_is_affected="Users transmitting sensitive data (logins, payments)",
        worst_case="Mass credential theft, compliance violations (PCI-DSS, GDPR)",
    ),
    OwaspCategory.A05_INJECTION.value: BusinessImpact(
        headline="Attackers may execute commands on your server or database",
        explanation=(
            "Injection flaws let an attacker send malicious input that "
            "your application executes as code.  This can leak your entire "
            "database, modify records, or take over the server."
        ),
        who_is_affected="Every user — the entire database may be compromised",
        worst_case="Complete database dump, server takeover, ransomware",
    ),
    OwaspCategory.A06_INSECURE_DESIGN.value: BusinessImpact(
        headline="The application's design has structural security weaknesses",
        explanation=(
            "Some vulnerabilities aren't coding bugs — they're design "
            "decisions that create risk.  For example, a password reset "
            "flow that doesn't verify identity, or an API that trusts "
            "client-side input for pricing."
        ),
        who_is_affected="Varies by specific design flaw",
        worst_case="Business logic abuse, financial loss, data manipulation",
    ),
    OwaspCategory.A07_AUTH_FAILURES.value: BusinessImpact(
        headline="User accounts may be compromised or sessions hijacked",
        explanation=(
            "Weaknesses in login, session management, or password "
            "policies let attackers take over user accounts or impersonate "
            "legitimate users."
        ),
        who_is_affected="Any user with an account on the application",
        worst_case="Account takeover, identity theft, unauthorised transactions",
    ),
    OwaspCategory.A08_INTEGRITY_FAILURES.value: BusinessImpact(
        headline="Code or data may be tampered with without detection",
        explanation=(
            "If the application doesn't verify the integrity of software "
            "updates, plugins, or data pipelines, an attacker can inject "
            "malicious code that runs with full trust."
        ),
        who_is_affected="The organisation and all users of the application",
        worst_case="Supply-chain attack, persistent backdoor",
    ),
    OwaspCategory.A09_LOGGING_FAILURES.value: BusinessImpact(
        headline="Security incidents may go undetected",
        explanation=(
            "Without proper logging and monitoring, attacks can continue "
            "for weeks or months before anyone notices.  There is no "
            "audit trail for forensic investigation."
        ),
        who_is_affected="The organisation — breach response is delayed",
        worst_case="Prolonged undetected breach, regulatory penalties for late"
        "disclosure",
    ),
    OwaspCategory.A10_EXCEPTIONAL_CONDITIONS.value: BusinessImpact(
        headline=(
            "The system may behave unsafely when it encounters unexpected conditions"
        ),
        explanation=(
            "When the application encounters errors, resource limits, or "
            "malformed input, it may fail in a way that bypasses security "
            "controls, leaks internal details, or crashes entirely.  Attackers "
            "deliberately trigger exceptional conditions to find these gaps."
        ),
        who_is_affected=(
            "All users — error conditions can expose data or disable protections"
        ),
        worst_case=(
            "Security bypass during error state, denial of service, information leakage"
        ),
    ),
}

_FALLBACK_IMPACT = BusinessImpact(
    headline="A security issue was identified",
    explanation=(
        "This finding indicates a potential security weakness that should be reviewed."
    ),
    who_is_affected="Depends on the specific vulnerability",
    worst_case="Varies — review the technical details for specifics",
)


def get_business_impact(finding: Finding) -> BusinessImpact:
    """Translate a technical finding into business-impact language."""
    impact = _BUSINESS_IMPACT.get(finding.owasp_category)
    if impact:
        return impact
    return _FALLBACK_IMPACT


def assess_risk_posture(findings: list[Finding]) -> RiskPosture:
    """Compute an overall risk posture from a list of findings.

    Scoring heuristic:
    - Each CRITICAL adds 25 points
    - Each HIGH adds 10 points
    - Each MEDIUM adds 3 points
    - Each LOW adds 1 point

    Thresholds:
    - >= 50: CRITICAL
    - >= 25: POOR
    - >= 10: MODERATE
    - >= 1:  GOOD
    - 0:     EXCELLENT
    """
    weights = {
        Severity.CRITICAL: 25,
        Severity.HIGH: 10,
        Severity.MEDIUM: 3,
        Severity.LOW: 1,
        Severity.INFO: 0,
    }
    score = sum(weights.get(f.severity, 0) for f in findings)

    if score >= 50:
        return RiskPosture.CRITICAL
    if score >= 25:
        return RiskPosture.POOR
    if score >= 10:
        return RiskPosture.MODERATE
    if score >= 1:
        return RiskPosture.GOOD
    return RiskPosture.EXCELLENT


def risk_posture_summary(posture: RiskPosture) -> str:
    """One-paragraph description of what the posture means."""
    summaries = {
        RiskPosture.CRITICAL: (
            "The application has critical security weaknesses that "
            "require immediate attention.  Exploitation is likely "
            "trivial and could result in data breach or full compromise."
        ),
        RiskPosture.POOR: (
            "Multiple significant vulnerabilities were found.  The "
            "application is at elevated risk of targeted or automated "
            "attack.  Remediation should be prioritised."
        ),
        RiskPosture.MODERATE: (
            "Some security issues were identified, mostly medium "
            "severity.  The application has a reasonable baseline but "
            "needs hardening in specific areas."
        ),
        RiskPosture.GOOD: (
            "Only minor issues were found.  The application follows "
            "most security best practices.  Address the remaining "
            "findings to reach an excellent posture."
        ),
        RiskPosture.EXCELLENT: (
            "No significant security issues were found.  The "
            "application appears well-hardened against common attacks."
        ),
    }
    return summaries[posture]
