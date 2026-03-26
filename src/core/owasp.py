from ..models.enums import OwaspCategory
from ..models.owasp import OwaspMapping

# Keyword -> OWASP mapping table

OWASP_MAPPINGS: dict[str, OwaspMapping] = {
    # A01 - Broken Access Control
    "idor": OwaspMapping(
        category=OwaspCategory.A01_BROKEN_ACCESS_CONTROL,
        description="Insecure Direct Object Reference",
        typical_cwes=("CWE-639",),
    ),
    "directory_traversal": OwaspMapping(
        category=OwaspCategory.A01_BROKEN_ACCESS_CONTROL,
        description="Path traversal allowing access to restricted files",
        typical_cwes=("CWE-22",),
    ),
    "cors_misconfiguration": OwaspMapping(
        category=OwaspCategory.A01_BROKEN_ACCESS_CONTROL,
        description="Overly permissive CORS policy",
        typical_cwes=("CWE-942",),
    ),
    "missing_access_control": OwaspMapping(
        category=OwaspCategory.A01_BROKEN_ACCESS_CONTROL,
        description="Missing function-level access control",
        typical_cwes=("CWE-285",),
    ),
    # SSRF is folded into A01 in 2025
    "ssrf": OwaspMapping(
        category=OwaspCategory.A01_BROKEN_ACCESS_CONTROL,
        description="Server-Side Request Forgery",
        typical_cwes=("CWE-918",),
    ),
    # A02 - Security Misconfiguration
    "security_misconfiguration": OwaspMapping(
        category=OwaspCategory.A02_SECURITY_MISCONFIGURATION,
        description="General security misconfiguration",
        typical_cwes=("CWE-16",),
    ),
    "directory_listing": OwaspMapping(
        category=OwaspCategory.A02_SECURITY_MISCONFIGURATION,
        description="Directory listing enabled on web server",
        typical_cwes=("CWE-548",),
    ),
    "default_credentials": OwaspMapping(
        category=OwaspCategory.A02_SECURITY_MISCONFIGURATION,
        description="Default or well-known credentials in use",
        typical_cwes=("CWE-798",),
    ),
    "verbose_errors": OwaspMapping(
        category=OwaspCategory.A02_SECURITY_MISCONFIGURATION,
        description="Verbose error messages revealing internal details",
        typical_cwes=("CWE-209",),
    ),
    "missing_security_headers": OwaspMapping(
        category=OwaspCategory.A02_SECURITY_MISCONFIGURATION,
        description="Missing or misconfigured security headers",
        typical_cwes=("CWE-693",),
    ),
    # A03 - Software Supply Chain Failures
    "outdated_component": OwaspMapping(
        category=OwaspCategory.A03_SUPPLY_CHAIN_FAILURES,
        description="Outdated software component with known vulnerabilities",
        typical_cwes=("CWE-1104",),
    ),
    "outdated_server": OwaspMapping(
        category=OwaspCategory.A03_SUPPLY_CHAIN_FAILURES,
        description="Server software version with known CVEs",
        typical_cwes=("CWE-1104",),
    ),
    "supply_chain": OwaspMapping(
        category=OwaspCategory.A03_SUPPLY_CHAIN_FAILURES,
        description="Software supply chain failure or compromise",
        typical_cwes=("CWE-1104", "CWE-829"),
    ),
    # A04 - Cryptographic Failures
    "weak_tls": OwaspMapping(
        category=OwaspCategory.A04_CRYPTOGRAPHIC_FAILURES,
        description="Weak TLS configuration or outdated protocols",
        typical_cwes=("CWE-326", "CWE-327"),
    ),
    "missing_hsts": OwaspMapping(
        category=OwaspCategory.A04_CRYPTOGRAPHIC_FAILURES,
        description="Missing HTTP Strict Transport Security header",
        typical_cwes=("CWE-523",),
    ),
    "cleartext_transmission": OwaspMapping(
        category=OwaspCategory.A04_CRYPTOGRAPHIC_FAILURES,
        description="Sensitive data transmitted over cleartext HTTP",
        typical_cwes=("CWE-319",),
    ),
    "weak_cipher": OwaspMapping(
        category=OwaspCategory.A04_CRYPTOGRAPHIC_FAILURES,
        description="Weak cipher suites accepted",
        typical_cwes=("CWE-326",),
    ),
    # A05 - Injection
    "sql_injection": OwaspMapping(
        category=OwaspCategory.A05_INJECTION,
        description="SQL Injection vulnerability",
        typical_cwes=("CWE-89",),
    ),
    "xss": OwaspMapping(
        category=OwaspCategory.A05_INJECTION,
        description="Cross-Site Scripting (reflected or stored)",
        typical_cwes=("CWE-79",),
    ),
    "command_injection": OwaspMapping(
        category=OwaspCategory.A05_INJECTION,
        description="OS command injection",
        typical_cwes=("CWE-78",),
    ),
    "xxe": OwaspMapping(
        category=OwaspCategory.A05_INJECTION,
        description="XML External Entity injection",
        typical_cwes=("CWE-611",),
    ),
    "crlf_injection": OwaspMapping(
        category=OwaspCategory.A05_INJECTION,
        description="CRLF injection / HTTP response splitting",
        typical_cwes=("CWE-93",),
    ),
    "open_redirect": OwaspMapping(
        category=OwaspCategory.A05_INJECTION,
        description="Unvalidated redirect or forward",
        typical_cwes=("CWE-601",),
    ),
    # A06 - Insecure Design
    "insecure_design": OwaspMapping(
        category=OwaspCategory.A06_INSECURE_DESIGN,
        description="Design-level security flaw",
        typical_cwes=("CWE-840",),
    ),
    # A07 - Authentication Failures
    "weak_password_policy": OwaspMapping(
        category=OwaspCategory.A07_AUTH_FAILURES,
        description="Weak password policy or no account lockout",
        typical_cwes=("CWE-521",),
    ),
    "session_fixation": OwaspMapping(
        category=OwaspCategory.A07_AUTH_FAILURES,
        description="Session fixation vulnerability",
        typical_cwes=("CWE-384",),
    ),
    "missing_csrf": OwaspMapping(
        category=OwaspCategory.A07_AUTH_FAILURES,
        description="Missing CSRF protection on state-changing forms",
        typical_cwes=("CWE-352",),
    ),
    # A08 - Software or Data Integrity Failures
    "insecure_deserialization": OwaspMapping(
        category=OwaspCategory.A08_INTEGRITY_FAILURES,
        description="Insecure deserialization",
        typical_cwes=("CWE-502",),
    ),
    "missing_sri": OwaspMapping(
        category=OwaspCategory.A08_INTEGRITY_FAILURES,
        description="Missing Subresource Integrity on external scripts",
        typical_cwes=("CWE-353",),
    ),
    # A09 - Security Logging and Alerting Failures
    "logging_failure": OwaspMapping(
        category=OwaspCategory.A09_LOGGING_FAILURES,
        description="Insufficient logging or monitoring",
        typical_cwes=("CWE-778",),
    ),
    # A10 - Mishandling of Exceptional Conditions
    "improper_error_handling": OwaspMapping(
        category=OwaspCategory.A10_EXCEPTIONAL_CONDITIONS,
        description="Improper handling of exceptional conditions",
        typical_cwes=("CWE-754", "CWE-755"),
    ),
    "fail_open": OwaspMapping(
        category=OwaspCategory.A10_EXCEPTIONAL_CONDITIONS,
        description="System fails open under error conditions",
        typical_cwes=("CWE-636",),
    ),
    "uncaught_exception": OwaspMapping(
        category=OwaspCategory.A10_EXCEPTIONAL_CONDITIONS,
        description=(
            "Uncaught exception leading to information disclosure or denial of service"
        ),
        typical_cwes=("CWE-248",),
    ),
}


def map_to_owasp(keyword: str) -> OwaspMapping | None:
    """Look up the OWASP mapping for a vulnerability keyword.

    The keyword is normalised to lowercase with spaces replaced by
    underscores before lookup.
    """
    key = keyword.lower().replace(" ", "_").replace("-", "_")
    return OWASP_MAPPINGS.get(key)


def map_cwe_to_owasp(cwe_id: str) -> OwaspMapping | None:
    """Find the OWASP mapping that includes the given CWE ID."""
    cwe_id = cwe_id.upper()
    if not cwe_id.startswith("CWE-"):
        cwe_id = f"CWE-{cwe_id}"
    for mapping in OWASP_MAPPINGS.values():
        if cwe_id in mapping.typical_cwes:
            return mapping
    return None


def all_categories() -> list[OwaspCategory]:
    """Return all OWASP Top 10 2025 categories."""
    return list(OwaspCategory)
