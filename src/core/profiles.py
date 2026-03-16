from ..models.profiles import ScanProfile

# ------------------------------------------------------------------
# Built-in profiles
# ------------------------------------------------------------------

PROFILES: dict[str, ScanProfile] = {
    "pre-launch": ScanProfile(
        name="pre-launch",
        display_name="Pre-Launch Audit",
        description=(
            "Comprehensive scan before a product or feature goes live.  "
            "Runs all available scanners with moderate aggressiveness."
        ),
        scanners=[
            "header_checks", "tls_checks", "misc_checks",
            "info_disclosure", "cookie_checks",
            "nmap", "sslyze", "wapiti",
        ],
        report_intro=(
            "This pre-launch security audit evaluates the application's "
            "readiness for production.  It covers the OWASP Top 10, TLS "
            "configuration, security headers, and common misconfigurations."
        ),
        estimated_duration="10-30 minutes",
        use_case="Before deploying a new application or major feature to production",
    ),
    "quick": ScanProfile(
        name="quick",
        display_name="Quick Surface Scan",
        description=(
            "Fast check using only built-in Python checks (no external "
            "tools).  Suitable for a first look or environments where "
            "external scanners are not installed."
        ),
        scanners=[
            "header_checks", "tls_checks", "misc_checks",
            "info_disclosure", "cookie_checks",
        ],
        report_intro=(
            "This quick surface scan checks security headers, TLS "
            "configuration, common misconfigurations, and information "
            "disclosure.  For deeper testing (injection, fuzzing), use "
            "the pre-launch or full profile."
        ),
        estimated_duration="1-3 minutes",
        use_case=(
            "Quick baseline check, CI pipeline gate, "
            "or when external tools are unavailable"
        ),
    ),
    "full": ScanProfile(
        name="full",
        display_name="Full OWASP Top 10 Audit",
        description=(
            "Maximum coverage: all built-in checks plus all external "
            "scanner integrations.  Includes active injection testing."
        ),
        scanners=[
            "header_checks", "tls_checks", "misc_checks",
            "info_disclosure", "cookie_checks",
            "nmap", "sslyze", "wapiti", "nikto", "nuclei",
        ],
        report_intro=(
            "This full OWASP Top 10 audit exercises every available "
            "scanner and check.  Active testing (injection, fuzzing) "
            "was performed within the authorised scope."
        ),
        estimated_duration="20-30 minutes",
        use_case="Thorough security assessment for compliance or due-diligence",
    ),
    "regression": ScanProfile(
        name="regression",
        display_name="Post-Release Regression",
        description=(
            "Lightweight scan to verify that a new release hasn't "
            "introduced regressions in security headers, TLS, or "
            "exposed paths.  Fast enough for CI."
        ),
        scanners=[
            "header_checks", "tls_checks", "misc_checks",
        ],
        report_intro=(
            "This regression scan checks whether security controls "
            "remain intact after a deployment.  It does not perform "
            "active injection testing."
        ),
        estimated_duration="30-60 seconds",
        use_case="Post-deployment CI check to catch security regressions",
    ),
    "compliance": ScanProfile(
        name="compliance",
        display_name="Compliance Due-Diligence",
        description=(
            "Focused on controls that auditors and compliance frameworks "
            "care about: TLS, headers, cookie flags, information "
            "disclosure, and port exposure."
        ),
        scanners=[
            "header_checks", "tls_checks", "misc_checks",
            "info_disclosure", "cookie_checks",
            "nmap", "sslyze",
        ],
        report_intro=(
            "This compliance-focused scan evaluates the target against "
            "controls commonly required by SOC 2, ISO 27001, PCI-DSS, "
            "and similar frameworks."
        ),
        estimated_duration="5-15 minutes",
        use_case="Preparing for a compliance audit or vendor security questionnaire",
    ),
}


def get_profile(name: str) -> ScanProfile:
    """Look up a profile by name, raising KeyError if not found."""
    if name not in PROFILES:
        available = ", ".join(PROFILES)
        raise KeyError(f"Unknown profile {name!r}.  Available: {available}")
    return PROFILES[name]


def list_profiles() -> list[ScanProfile]:
    """Return all profiles in display order."""
    return list(PROFILES.values())
