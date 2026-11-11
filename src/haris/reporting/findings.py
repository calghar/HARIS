from ..models import Finding, ScanSession, VerificationTier

UNCLASSIFIED = "unclassified"


def rule_id(finding: Finding) -> str:
    """Stable id of the finding's vulnerability class."""
    return finding.vuln_class or UNCLASSIFIED


def report_findings(session: ScanSession) -> list[Finding]:
    """Canonical findings (one per fingerprint); raw findings if never correlated."""
    if session.correlated:
        return [c.canonical for c in session.correlated]
    return session.all_findings


def split_findings(session: ScanSession) -> tuple[list[Finding], list[Finding]]:
    """(active, inactive): inactive are refuted or suppressed."""
    findings = report_findings(session)
    return (
        [f for f in findings if f.is_active],
        [f for f in findings if not f.is_active],
    )


def inactive_reason(finding: Finding) -> str:
    """Why a finding is not active: suppression reason or ``refuted``."""
    if finding.suppression is not None:
        return f"suppressed: {finding.suppression.reason}"
    if finding.verification.tier == VerificationTier.REFUTED:
        return "refuted"
    return ""
