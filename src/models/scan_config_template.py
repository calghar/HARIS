"""Reusable scan configuration template model."""

import uuid
from typing import Any

from pydantic import BaseModel, Field


class ScanConfigTemplate(BaseModel):
    """A saved set of scan parameters that can be reused across scans.

    Stores both global scan settings (profile, rate limit, auth) and
    per-scanner option overrides that map to each tool's real
    template/plugin system (Nuclei tags, Nikto tuning, Nmap script
    categories, Wapiti modules, etc.).
    """

    template_id: str = Field(
        default_factory=lambda: uuid.uuid4().hex[:10],
    )
    name: str
    description: str = ""

    # Global scan settings
    profile: str = "quick"
    rate_limit_rps: float = 10.0
    max_requests: int = 10_000
    excluded_paths: list[str] = Field(default_factory=list)
    auth_method: str = "none"  # none | header | cookie
    report_formats: list[str] = Field(
        default_factory=lambda: ["markdown", "json"],
    )
    llm_enrichment: bool = False
    llm_backend: str = ""

    # Per-scanner option overrides keyed by scanner name.
    # Merged over default_config.yaml defaults during scan execution.
    #
    # Supported keys per scanner:
    #   nuclei:  tags, severity, rate_limit, timeout
    #   nikto:   plugins, tuning, timeout
    #   wapiti:  modules, scope, max_scan_time, max_links, timeout
    #   nmap:    ports, script_categories, timeout
    #   sslyze:  timeout
    #   header_checks:  follow_redirects, timeout
    #   tls_checks:     cert_expiry_warn_days, timeout
    #   misc_checks:    check_cors, check_redirect, check_sensitive_paths
    #   info_disclosure: check_error_pages, check_debug_endpoints,
    #                    check_html_comments, check_version_endpoints
    #   cookie_checks:  timeout
    scanner_options: dict[str, dict[str, Any]] = Field(
        default_factory=dict,
    )

    # Metadata
    tags: list[str] = Field(default_factory=list)
    is_default: bool = False
    created_at: str = ""
    updated_at: str = ""
