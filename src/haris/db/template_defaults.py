from ..models.scan_config_template import ScanConfigTemplate


def default_templates() -> list[ScanConfigTemplate]:
    return [
        ScanConfigTemplate(
            template_id="builtin-01",
            name="Quick Surface Scan",
            description=("Fast built-in checks only. Good for first look or CI gates."),
            profile="quick",
            rate_limit_rps=10.0,
            max_requests=10_000,
            llm_enrichment=False,
            scanner_options={},
            tags=["built-in", "ci", "fast"],
            is_default=True,
        ),
        ScanConfigTemplate(
            template_id="builtin-02",
            name="Pre-Launch Audit",
            description=(
                "Comprehensive scan before go-live. Built-in checks "
                "plus network scanners."
            ),
            profile="pre-launch",
            rate_limit_rps=10.0,
            max_requests=10_000,
            llm_enrichment=True,
            scanner_options={
                "nmap": {
                    "ports": "80,443,8080,8443,8000,3000,9090",
                    "script_categories": ["default", "safe", "vuln"],
                },
                "wapiti": {
                    "scope": "folder",
                    "modules": "all",
                    "max_links": 500,
                },
            },
            tags=["built-in", "pre-launch"],
        ),
        ScanConfigTemplate(
            template_id="builtin-03",
            name="Full OWASP Top 10",
            description=(
                "Maximum coverage with all scanners including active injection testing."
            ),
            profile="full",
            rate_limit_rps=5.0,
            max_requests=50_000,
            llm_enrichment=True,
            scanner_options={
                "nuclei": {
                    "template_dirs": [
                        "http/exposures",
                        "http/exposed-panels",
                        "http/vulnerabilities",
                        "http/default-logins",
                        "http/takeovers",
                        "dast",
                    ],
                    "severity": [
                        "critical",
                        "high",
                        "medium",
                        "low",
                        "info",
                    ],
                    "exclude_tags": ["dos", "fuzz"],
                    "rate_limit": 100,
                },
                "nikto": {
                    "tuning": ["1", "2", "3", "b", "d", "e"],
                    "plugins": [
                        "@@DEFAULT",
                        "shellshock",
                        "headers",
                        "springboot",
                    ],
                },
                "wapiti": {
                    "scope": "domain",
                    "modules": "all",
                    "max_scan_time": 900,
                    "max_links": 1000,
                },
                "nmap": {
                    "ports": ("80,443,8080,8443,8000,8888,3000,5000,9090,9443"),
                    "script_categories": [
                        "default",
                        "safe",
                        "vuln",
                        "discovery",
                    ],
                },
            },
            tags=["built-in", "comprehensive", "owasp"],
        ),
        ScanConfigTemplate(
            template_id="builtin-04",
            name="Regression Check",
            description=(
                "Lightweight post-deployment check. Headers, TLS, "
                "and misconfiguration only."
            ),
            profile="regression",
            rate_limit_rps=20.0,
            max_requests=5_000,
            llm_enrichment=False,
            scanner_options={
                "misc_checks": {"check_sensitive_paths": False},
                "tls_checks": {"cert_expiry_warn_days": 30},
            },
            tags=["built-in", "ci", "fast", "regression"],
        ),
        ScanConfigTemplate(
            template_id="builtin-05",
            name="Compliance Audit",
            description=(
                "Focused on SOC 2 / ISO 27001 / PCI-DSS control verification."
            ),
            profile="compliance",
            rate_limit_rps=10.0,
            max_requests=20_000,
            llm_enrichment=True,
            scanner_options={
                "nmap": {
                    "ports": "80,443,8080,8443,22,3389",
                    "script_categories": [
                        "default",
                        "safe",
                        "vuln",
                        "auth",
                    ],
                },
                "tls_checks": {"cert_expiry_warn_days": 60},
                "info_disclosure": {
                    "check_error_pages": True,
                    "check_version_endpoints": True,
                },
            },
            tags=["built-in", "compliance", "audit"],
        ),
    ]
