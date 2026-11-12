from ..models.enums import OwaspCategory
from ..models.owasp import AgenticRisk, AiRisk, LlmRisk, McpRisk, OwaspMapping

AI_RISKS: dict[str, AiRisk] = {
    risk.value.split(" - ")[0]: risk
    for risks in (LlmRisk, AgenticRisk, McpRisk)
    for risk in risks
}

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

# Class id -> existing keyword whose first CWE equals the class primary CWE.
_CLASS_KEYWORDS: dict[str, str] = {
    "xss_stored": "xss",
    "xss_reflected": "xss",
    "sqli_time": "sql_injection",
    "sqli_error": "sql_injection",
    "path_traversal": "directory_traversal",
    "open_redirect": "open_redirect",
    "ssrf": "ssrf",
    "xxe": "xxe",
    "command_injection": "command_injection",
    "csrf": "missing_csrf",
    "cleartext_password_submission": "cleartext_transmission",
    "no_https": "cleartext_transmission",
    "no_https_redirect": "cleartext_transmission",
    "weak_hsts": "cleartext_transmission",
    "missing_header": "missing_security_headers",
    "weak_csp": "missing_security_headers",
    "dns_missing_caa": "missing_security_headers",
    "tls_weak_protocol": "weak_tls",
    "tls_weak_cipher": "weak_cipher",
    "cors_misconfiguration": "cors_misconfiguration",
    "directory_listing": "directory_listing",
    "verbose_error": "verbose_errors",
    "missing_sri": "missing_sri",
    "cookie_scope": "security_misconfiguration",
    "http_trace": "security_misconfiguration",
}


def _class_mapping(category: OwaspCategory, cwe: str, description: str) -> OwaspMapping:
    return OwaspMapping(category=category, description=description, typical_cwes=(cwe,))


_INFO_EXPOSURE = _class_mapping(
    OwaspCategory.A02_SECURITY_MISCONFIGURATION,
    "CWE-200",
    "Information exposed to a client",
)
_INSECURE_COOKIE = _class_mapping(
    OwaspCategory.A02_SECURITY_MISCONFIGURATION,
    "CWE-614",
    "Cookie without the Secure flag",
)
_DNS_SPOOFING = _class_mapping(
    OwaspCategory.A02_SECURITY_MISCONFIGURATION,
    "CWE-290",
    "Missing mail spoofing protection",
)
_CRYPTO = OwaspCategory.A04_CRYPTOGRAPHIC_FAILURES

# Class id -> mapping. ``ai_*`` classes carry their own LLM/agentic risk ids.
CLASS_OWASP: dict[str, OwaspMapping] = {
    **{cls: OWASP_MAPPINGS[keyword] for cls, keyword in _CLASS_KEYWORDS.items()},
    "unrestricted_upload": _class_mapping(
        OwaspCategory.A06_INSECURE_DESIGN, "CWE-434", "Unrestricted file upload"
    ),
    "version_disclosure": _INFO_EXPOSURE,
    "banner_disclosure": _INFO_EXPOSURE,
    "cookie_name_disclosure": _INFO_EXPOSURE,
    "graphql_introspection": _INFO_EXPOSURE,
    "api_docs_exposed": _INFO_EXPOSURE,
    "sensitive_file": _class_mapping(
        OwaspCategory.A02_SECURITY_MISCONFIGURATION, "CWE-538", "Sensitive file exposed"
    ),
    "insecure_cookie": _INSECURE_COOKIE,
    "cookie_missing_secure": _INSECURE_COOKIE,
    "cookie_missing_httponly": _class_mapping(
        OwaspCategory.A02_SECURITY_MISCONFIGURATION,
        "CWE-1004",
        "Cookie without HttpOnly",
    ),
    "cookie_samesite": _class_mapping(
        OwaspCategory.A02_SECURITY_MISCONFIGURATION,
        "CWE-1275",
        "Cookie without SameSite",
    ),
    "cookie_lifetime": _class_mapping(
        OwaspCategory.A07_AUTH_FAILURES,
        "CWE-613",
        "Session cookie with excessive lifetime",
    ),
    "tls_cert_expired": _class_mapping(_CRYPTO, "CWE-298", "Expired TLS certificate"),
    "tls_cert_hostname": _class_mapping(
        _CRYPTO, "CWE-297", "TLS certificate host mismatch"
    ),
    "tls_cert_untrusted": _class_mapping(
        _CRYPTO, "CWE-295", "Untrusted TLS certificate"
    ),
    "http_methods": _class_mapping(
        OwaspCategory.A02_SECURITY_MISCONFIGURATION,
        "CWE-749",
        "Dangerous HTTP method enabled",
    ),
    "dns_missing_spf": _DNS_SPOOFING,
    "dns_missing_dmarc": _DNS_SPOOFING,
    "cache_sensitive": _class_mapping(
        OwaspCategory.A02_SECURITY_MISCONFIGURATION,
        "CWE-525",
        "Sensitive response cacheable",
    ),
    "html_comment_leak": _class_mapping(
        OwaspCategory.A02_SECURITY_MISCONFIGURATION,
        "CWE-615",
        "Sensitive data in HTML comments",
    ),
}


def map_class_to_owasp(class_id: str) -> OwaspMapping | None:
    """Look up the OWASP mapping for a canonical vulnerability class id."""
    return CLASS_OWASP.get(class_id)


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


def map_ai_risk(risk_id: str) -> AiRisk | None:
    """Look up an OWASP LLM, Agentic or MCP risk by id (``LLM01:2026``, ``ASI03``)."""
    return AI_RISKS.get(risk_id)


def all_categories() -> list[OwaspCategory]:
    """Return all OWASP Top 10 2025 categories."""
    return list(OwaspCategory)
