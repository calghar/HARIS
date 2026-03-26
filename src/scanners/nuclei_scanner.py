import json
import logging
import tempfile
from typing import Any

from ..core.decorators import handle_scanner_errors, register_scanner
from ..core.scanner import BaseScanner
from ..models import Confidence, Finding, ScannerResult, Severity, Target
from ..models.scan_context import ScanContext

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Severity mapping
# ---------------------------------------------------------------------------

# Nuclei severity strings map directly onto our internal model.
_NUCLEI_SEVERITY_MAP: dict[str, Severity] = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
    "info": Severity.INFO,
    "unknown": Severity.INFO,
}

# ---------------------------------------------------------------------------
# OWASP tag mapping
# ---------------------------------------------------------------------------

# Nuclei templates carry ``tags`` in their ``info`` block and a
# ``matcher-name`` / ``template-id`` at the result level.  We derive our
# internal OWASP tags by scanning those fields against this lookup table.
# Keys are lowercase substrings; values are OWASP-aligned tag lists.
# Evaluation order matters: the first key that matches wins.
_NUCLEI_TAG_MAP: dict[str, list[str]] = {
    # Injection
    "sql": ["sql_injection"],
    "sqli": ["sql_injection"],
    "xss": ["xss"],
    "ssti": ["ssti"],
    "xxe": ["xxe"],
    "ssrf": ["ssrf"],
    "command-injection": ["command_injection"],
    "rce": ["command_injection"],
    "code-injection": ["command_injection"],
    "lfi": ["directory_traversal"],
    "path-traversal": ["directory_traversal"],
    "open-redirect": ["open_redirect"],
    "redirect": ["open_redirect"],
    # Authentication / access control
    "default-login": ["default_credentials"],
    "default-credentials": ["default_credentials"],
    "auth-bypass": ["broken_authentication"],
    "authentication-bypass": ["broken_authentication"],
    "login-panel": ["exposed_panel"],
    "panel": ["exposed_panel"],
    "admin-panel": ["exposed_panel"],
    "exposure": ["sensitive_data_exposure"],
    "disclosure": ["sensitive_data_exposure"],
    "sensitive": ["sensitive_data_exposure"],
    "backup": ["security_misconfiguration"],
    "config": ["security_misconfiguration"],
    "misconfiguration": ["security_misconfiguration"],
    "misconfig": ["security_misconfiguration"],
    "directory-listing": ["directory_listing"],
    "listing": ["directory_listing"],
    # CVE / outdated components
    "cve": ["outdated_component"],
    "cnvd": ["outdated_component"],
    "edb": ["outdated_component"],
    # Headers / TLS / network
    "headers": ["missing_security_headers"],
    "cors": ["missing_security_headers"],
    "tls": ["weak_tls"],
    "ssl": ["weak_tls"],
    # DNS / cloud
    "dns": ["security_misconfiguration"],
    "takeover": ["security_misconfiguration"],
    "cloud": ["security_misconfiguration"],
    # Tech fingerprint (informational)
    "tech": ["security_misconfiguration"],
}

# Default template directories for selective scanning.
# Focused on checks NOT already covered by other HARIS scanners:
#   SKIP ssl (38)                — SSLyze + tls_checks cover TLS deeply
#   SKIP http/technologies (866) — used in Phase 1 only
# Users can add any of the above via template_dirs in scan config templates.
DEFAULT_TEMPLATE_DIRS: list[str] = [
    "http/cves",  # 3830 — known CVE checks (largest, most impactful)
    "http/exposures",  # 683 — exposed files, backups, cloud storage, secrets
    "http/exposed-panels",  # 1351 — admin panels, CMS logins, management UIs
    "http/vulnerabilities",  # 934 — injection, XSS, SSRF beyond Wapiti
    "http/default-logins",  # 270 — default credentials (unique to nuclei)
    "http/takeovers",  # 74  — subdomain takeover detection
    "http/misconfiguration",  # 920 — misconfigs, security headers, CORS, etc.
    "dast",  # 249 — dynamic application security testing
]

# Template directory used for technology fingerprinting (Phase 1).
TECH_FINGERPRINT_DIR = "http/technologies"

# ---------------------------------------------------------------------------
# Technology → Nuclei tag/workflow mapping
# ---------------------------------------------------------------------------
# Maps detected technology keywords to Nuclei tags and optional workflow files.
# The scanner uses this to create a targeted Phase 2 template selection.
TECH_TAG_MAP: dict[str, list[str]] = {
    "wordpress": ["wordpress", "wp-plugin", "wp-theme"],
    "drupal": ["drupal"],
    "joomla": ["joomla"],
    "magento": ["magento"],
    "shopify": ["shopify"],
    "apache": ["apache"],
    "nginx": ["nginx"],
    "iis": ["iis"],
    "tomcat": ["tomcat", "apache-tomcat"],
    "php": ["php"],
    "asp.net": ["asp"],
    "nodejs": ["nodejs"],
    "express": ["express", "nodejs"],
    "django": ["django", "python"],
    "flask": ["flask", "python"],
    "laravel": ["laravel", "php"],
    "rails": ["rails", "ruby"],
    "spring": ["spring", "java"],
    "jenkins": ["jenkins"],
    "gitlab": ["gitlab"],
    "grafana": ["grafana"],
    "jira": ["jira", "atlassian"],
    "confluence": ["confluence", "atlassian"],
    "elasticsearch": ["elasticsearch", "elastic"],
    "kibana": ["kibana", "elastic"],
    "docker": ["docker"],
    "kubernetes": ["kubernetes", "k8s"],
    "aws": ["aws", "amazon"],
    "azure": ["azure"],
    "gcp": ["gcp", "google"],
    "cloudflare": ["cloudflare"],
    "react": ["react"],
    "nextjs": ["nextjs"],
    "angular": ["angular"],
    "vue": ["vue"],
    "weblogic": ["weblogic", "oracle"],
    "websphere": ["websphere", "ibm"],
    "coldfusion": ["coldfusion", "adobe"],
    "sap": ["sap"],
    "citrix": ["citrix"],
    "fortinet": ["fortinet"],
    "sonicwall": ["sonicwall"],
    "paloalto": ["paloalto"],
    "vmware": ["vmware"],
    "zimbra": ["zimbra"],
    "moodle": ["moodle"],
    "typo3": ["typo3"],
    "ghost": ["ghost"],
    "struts": ["struts", "apache-struts"],
}

# Map tech → workflow YAML file (relative to nuclei-templates root)
TECH_WORKFLOW_MAP: dict[str, str] = {
    "wordpress": "workflows/wordpress-workflow.yaml",
    "drupal": "workflows/drupal-workflow.yaml",
    "joomla": "workflows/joomla-workflow.yaml",
    "magento": "workflows/magento-workflow.yaml",
    "apache": "workflows/apache-workflow.yaml",
    "tomcat": "workflows/apache-tomcat-workflow.yaml",
    "jenkins": "workflows/jenkins-workflow.yaml",
    "gitlab": "workflows/gitlab-workflow.yaml",
    "grafana": "workflows/grafana-workflow.yaml",
    "jira": "workflows/jira-workflow.yaml",
    "confluence": "workflows/confluence-workflow.yaml",
    "spring": "workflows/springboot-workflow.yaml",
    "weblogic": "workflows/weblogic-workflow.yaml",
    "zimbra": "workflows/zimbra-workflow.yaml",
    "moodle": "workflows/moodle-workflow.yaml",
}

# Confidence levels keyed by Nuclei severity: higher severity => higher confidence.
_NUCLEI_CONFIDENCE_MAP: dict[str, Confidence] = {
    "critical": Confidence.CONFIRMED,
    "high": Confidence.CONFIRMED,
    "medium": Confidence.FIRM,
    "low": Confidence.FIRM,
    "info": Confidence.TENTATIVE,
    "unknown": Confidence.TENTATIVE,
}


def _derive_tags(
    template_id: str,
    matcher_name: str,
    nuclei_tags: list[str],
) -> list[str]:
    """Derive internal OWASP tags from Nuclei output fields.

    The function inspects (in order of preference):

    1. The Nuclei template tags (``info.tags``).
    2. The matcher name (``matcher-name``).
    3. The template ID (``template-id``).

    For each candidate string the function checks whether any key from
    :data:`_NUCLEI_TAG_MAP` appears as a substring, accumulating matched
    OWASP tags without duplicates.

    Args:
        template_id: Nuclei template identifier, e.g. ``"CVE-2021-44228-log4j-rce"``.
        matcher_name: The specific matcher that fired, e.g. ``"log4j-rce"``.
        nuclei_tags: The list of tags declared in the template's ``info`` block.

    Returns:
        De-duplicated list of OWASP tag strings.  Falls back to
        ``["security_misconfiguration"]`` when no mapping is found.
    """
    owasp_tags: list[str] = []
    seen: set[str] = set()

    # Build the set of Nuclei-side strings to probe.
    candidates = [t.lower() for t in nuclei_tags]
    if matcher_name:
        candidates.append(matcher_name.lower())
    if template_id:
        candidates.append(template_id.lower())

    for candidate in candidates:
        for key, mapped_tags in _NUCLEI_TAG_MAP.items():
            if key in candidate:
                for tag in mapped_tags:
                    if tag not in seen:
                        owasp_tags.append(tag)
                        seen.add(tag)

    return owasp_tags if owasp_tags else ["security_misconfiguration"]


@register_scanner
class NucleiScanner(BaseScanner):
    """Adapter for the Nuclei template-based vulnerability scanner.

    Uses a **multi-phase scanning strategy**:

    1. **Phase 1 — Tech fingerprinting** (``http/technologies/`` templates):
       Identifies the target's technology stack quickly.
    2. **Phase 2a — Broad scan**: Runs default template directories (exposures,
       misconfigs, panels, default-logins, takeovers, DAST) without tag
       filtering for full vulnerability coverage.
    3. **Phase 2b — Tech-targeted scan**: If specific technologies were detected,
       runs templates matching tech-specific tags and workflows.

    Cross-scanner intelligence from :class:`~src.models.scan_context.ScanContext`
    further refines template selection using Nmap service detection,
    Nikto server headers, and Wapiti crawl results.

    Requires ``nuclei`` to be installed and on PATH.
    Install: ``go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest``

    Options (pass via constructor or :meth:`configure`):

    ``timeout`` (int, default 3600)
        Maximum seconds to wait for the nuclei run to complete.
    ``template_dirs`` (list[str], default [])
        Relative directory names within nuclei's built-in template tree.
        When set, overrides the default two-phase strategy.
    ``templates`` (list[str], default [])
        Explicit absolute template paths (from TemplateManager).
    ``tags`` (list[str], default [])
        Only run templates matching these tags (``-tags`` flag).
    ``severity`` (list[str], default [])
        Restrict to specific severity levels (``-severity`` flag).
    ``exclude_tags`` (list[str], default [])
        Exclude templates with these tags (``-etags`` flag).
    ``rate_limit`` (int, default 100)
        Maximum HTTP requests per second (``-rate-limit`` flag).
    ``max_host_errors`` (int, default 500)
        Maximum errors before skipping a host.
    ``enable_interactsh`` (bool, default False)
        Enable OOB interaction server for blind vulnerability detection.
    ``skip_tech_detection`` (bool, default False)
        Skip Phase 1 tech fingerprinting (use only cross-scanner context).
    ``extra_args`` (list[str], default [])
        Additional CLI flags appended verbatim.

    Example::

        scanner = NucleiScanner(options={
            "severity": ["high", "critical"],
            "enable_interactsh": True,
        })
        result = scanner.scan(target, context=scan_context)
    """

    name = "nuclei"
    version = "3.x"
    description = "Template-based CVE, misconfiguration, and exposure scanner"

    def __init__(self, options: dict[str, Any] | None = None) -> None:
        super().__init__(options)
        self.options.setdefault("timeout", 3600)
        self.options.setdefault("templates", [])
        self.options.setdefault("tags", [])
        self.options.setdefault("severity", [])
        self.options.setdefault("exclude_tags", [])
        self.options.setdefault("rate_limit", 100)
        self.options.setdefault("max_host_errors", 500)
        self.options.setdefault("concurrency", 10)
        self.options.setdefault("bulk_size", 10)
        self.options.setdefault("template_dirs", [])
        self.options.setdefault("extra_args", [])
        self.options.setdefault("enable_interactsh", False)
        self.options.setdefault("skip_tech_detection", False)

    @handle_scanner_errors
    def scan(self, target: Target, context: ScanContext | None = None) -> ScannerResult:
        """Run a multi-phase Nuclei scan against *target*.

        **Phase 1** — Technology fingerprinting (fast, info-only):
        Runs ``http/technologies/`` templates to detect the target's
        tech stack.  Results are merged into *context* for later use.

        **Phase 2a** — Broad vulnerability scan:
        Runs the default template directories (exposures, panels,
        vulnerabilities, misconfigs, takeovers, default-logins, DAST)
        WITHOUT any tag filter, ensuring full coverage.

        **Phase 2b** — Tech-targeted scan (conditional):
        If Phase 1 or cross-scanner context detected specific technologies,
        runs templates matching tech-specific tags and workflows
        (e.g. ``-tags wordpress`` + ``workflows/wordpress-workflow.yaml``).
        Only runs when meaningful tech was detected.

        If the user has explicitly set ``template_dirs``, ``templates``,
        or ``tags``, those override the multi-phase strategy entirely.

        Args:
            target: The :class:`~models.target.Target` to scan.
            context: Optional :class:`~models.scan_context.ScanContext`
                with intelligence from earlier scanners.

        Returns:
            A :class:`~models.scanner.ScannerResult` containing findings
            from both phases and any errors encountered.
        """
        if not self._check_tool_available("nuclei"):
            return ScannerResult(
                scanner_name=self.name,
                errors=["nuclei is not installed or not on PATH"],
            )

        all_findings: list[Finding] = []
        all_errors: list[str] = []
        all_raw: list[str] = []
        context = context or ScanContext()

        # Check if user has explicit template selection (skip two-phase)
        has_explicit = bool(
            self.options.get("template_dirs") or self.options.get("tags")
        )

        # ── Phase 1: Technology fingerprinting ────────────────────
        if not has_explicit and not self.options.get("skip_tech_detection"):
            phase1_findings, phase1_errors, phase1_raw = self._run_phase(
                target,
                template_dirs=[TECH_FINGERPRINT_DIR],
                phase_label="phase1-tech",
            )
            all_raw.append(phase1_raw)
            all_errors.extend(phase1_errors)

            # Extract detected technologies from fingerprinting results
            detected_techs = self._extract_technologies(phase1_findings)
            context.add_technologies(detected_techs)
            logger.info(
                "Nuclei Phase 1: detected %d technologies: %s",
                len(detected_techs),
                ", ".join(detected_techs[:20]),
            )
            # Phase 1 findings are informational — include them
            all_findings.extend(phase1_findings)

        # ── Phase 2: Targeted vulnerability scan ──────────────────
        target_urls = self._build_url_list(target, context)
        phase2_template_dirs, phase2_tags, phase2_workflows = (
            self._resolve_targeted_selection(context, has_explicit)
        )

        # Phase 2a: Broad scan with default/explicit template dirs (NO tag filter)
        # Tags are deliberately NOT passed here — they would AND-filter
        # and exclude most templates.
        phase2a_findings, phase2a_errors, phase2a_raw = self._run_phase(
            target,
            template_dirs=phase2_template_dirs,
            url_list=target_urls,
            phase_label="phase2-broad",
        )
        all_raw.append(phase2a_raw)
        all_findings.extend(phase2a_findings)
        all_errors.extend(phase2a_errors)

        # Phase 2b: Tech-targeted scan (tags + workflows from detected tech)
        # Only runs if we have tech-specific tags or workflows to add.
        if phase2_tags or phase2_workflows:
            phase2b_findings, phase2b_errors, phase2b_raw = self._run_phase(
                target,
                extra_tags=phase2_tags,
                workflows=phase2_workflows,
                url_list=target_urls,
                phase_label="phase2-targeted",
            )
            all_raw.append(phase2b_raw)
            all_findings.extend(phase2b_findings)
            all_errors.extend(phase2b_errors)

        combined_raw = "\n".join(all_raw)
        return ScannerResult(
            scanner_name=self.name,
            raw_output=combined_raw,
            findings=all_findings,
            errors=all_errors,
        )

    def parse_results(self, raw_output: str) -> list[Finding]:
        """Parse Nuclei JSONL output into :class:`~core.finding.Finding` objects.

        Each non-empty line of *raw_output* is expected to be a JSON object
        matching the Nuclei result schema.  Relevant fields:

        - ``template-id`` (str): unique template identifier
        - ``info.name`` (str): human-readable template name
        - ``info.description`` (str): template description
        - ``info.severity`` (str): ``info|low|medium|high|critical``
        - ``info.tags`` (list[str]): template classification tags
        - ``info.reference`` (list[str]|str): advisory references
        - ``info.remediation`` (str): optional remediation text
        - ``info.classification.cve-id`` (list[str]): CVE identifiers
        - ``info.classification.cwe-id`` (list[str]): CWE identifiers
        - ``info.classification.cvss-score`` (float): CVSS score
        - ``matcher-name`` (str): specific matcher that fired
        - ``matched-at`` (str): URL or host where the match occurred
        - ``extracted-results`` (list[str]): values captured by extractors
        - ``request`` (str): raw HTTP request sent
        - ``response`` (str): raw HTTP response received (may be absent)
        - ``ip`` (str): resolved IP address of the target

        Args:
            raw_output: Raw JSONL string produced by ``nuclei -jsonl``.

        Returns:
            List of :class:`~core.finding.Finding` objects.  Lines that
            cannot be parsed are skipped with a WARNING log entry.
        """
        findings: list[Finding] = []

        for line_num, line in enumerate(raw_output.splitlines(), start=1):
            line = line.strip()
            if not line:
                continue

            try:
                result = json.loads(line)
            except json.JSONDecodeError as exc:
                logger.warning(
                    "Skipping unparseable Nuclei JSONL line %d: %s", line_num, exc
                )
                continue

            finding = self._result_to_finding(result)
            if finding is not None:
                findings.append(finding)

        return findings

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _result_to_finding(self, result: dict[str, Any]) -> Finding | None:
        """Convert a single Nuclei result dict to a :class:`Finding`.

        Args:
            result: A parsed JSON object from Nuclei's JSONL output.

        Returns:
            A :class:`~core.finding.Finding`, or ``None`` if the result
            dict is missing mandatory fields.
        """
        template_id: str = result.get("template-id", "")
        info: dict[str, Any] = result.get("info", {})

        name: str = info.get("name", template_id or "Unknown finding")
        description: str = info.get("description", "")
        severity_raw: str = info.get("severity", "info").lower()
        nuclei_tags: list[str] = info.get("tags", [])
        matcher_name: str = result.get("matcher-name", "")
        matched_at: str = result.get("matched-at", "")
        extracted: list[str] = result.get("extracted-results", [])
        request_example: str = result.get("request", "")
        response_snippet: str = result.get("response", "")

        if not name and not template_id:
            logger.debug("Skipping Nuclei result with no name or template-id")
            return None

        severity = _NUCLEI_SEVERITY_MAP.get(severity_raw, Severity.INFO)
        confidence = _NUCLEI_CONFIDENCE_MAP.get(severity_raw, Confidence.TENTATIVE)
        tags = _derive_tags(template_id, matcher_name, nuclei_tags)

        # Build reference list from template info.
        raw_refs = info.get("reference", [])
        if isinstance(raw_refs, str):
            raw_refs = [raw_refs]
        references: list[str] = [r for r in raw_refs if isinstance(r, str)]

        # Extract CVE / CWE from classification block.
        classification: dict[str, Any] = info.get("classification", {})
        cve_ids: list[str] = classification.get("cve-id", []) or []
        cwe_ids: list[str] = classification.get("cwe-id", []) or []
        cvss_score: float | None = classification.get("cvss-score")

        # Enrich references with CVE advisory URLs.
        for cve in cve_ids:
            cve_url = f"https://nvd.nist.gov/vuln/detail/{cve}"
            if cve_url not in references:
                references.append(cve_url)

        # Build a richer title when CVEs are present.
        if cve_ids:
            title = f"{name} ({', '.join(cve_ids)})"
        elif matcher_name:
            title = f"{name} [{matcher_name}]"
        else:
            title = name

        # Evidence: extracted values or response snippet.
        evidence_parts: list[str] = []
        if extracted:
            evidence_parts.append(f"Extracted: {'; '.join(extracted[:5])}")
        if response_snippet:
            # Limit response to first 300 chars to avoid bloating the model.
            snippet = response_snippet[:300]
            evidence_parts.append(f"Response snippet: {snippet}")
        evidence = "\n".join(evidence_parts)

        # Remediation: prefer template-provided text, fall back to generic.
        remediation: str = info.get("remediation", "")
        if not remediation:
            remediation = self._generic_remediation(tags, severity)

        # CWE: join first entry as string (e.g. "CWE-79").
        cwe_str = cwe_ids[0] if cwe_ids else ""

        # CVSS metadata stored in raw_data for downstream processing.
        raw_data: dict[str, Any] = {
            "template-id": template_id,
            "matcher-name": matcher_name,
            "matched-at": matched_at,
            "nuclei-tags": nuclei_tags,
            "extracted-results": extracted,
            "cve-id": cve_ids,
            "cwe-id": cwe_ids,
        }
        if cvss_score is not None:
            raw_data["cvss-score"] = cvss_score

        return Finding(
            title=title[:200],
            description=description or name,
            severity=severity,
            confidence=confidence,
            cwe_id=cwe_str,
            url=matched_at,
            evidence=evidence,
            request_example=request_example,
            response_snippet=response_snippet[:500] if response_snippet else "",
            remediation=remediation,
            references=references,
            scanner=self.name,
            tags=tags,
            raw_data=raw_data,
        )

    def _run_phase(
        self,
        target: Target,
        *,
        template_dirs: list[str] | None = None,
        extra_tags: list[str] | None = None,
        workflows: list[str] | None = None,
        url_list: list[str] | None = None,
        phase_label: str = "",
    ) -> tuple[list[Finding], list[str], str]:
        """Execute a single Nuclei invocation and return parsed results.

        Returns:
            A tuple of (findings, errors, raw_stdout).
        """
        cmd = self._build_command(
            target,
            template_dirs=template_dirs,
            extra_tags=extra_tags,
            workflows=workflows,
            url_list=url_list,
        )
        logger.info("nuclei [%s] command: %s", phase_label, " ".join(cmd))

        returncode, stdout, stderr = self._run_command(
            cmd, timeout=self.options["timeout"]
        )

        filtered_stderr = "\n".join(
            line for line in stderr.splitlines() if "Unsolicited response" not in line
        ).strip()

        logger.info(
            "nuclei [%s] exit=%d stdout_lines=%d stderr_len=%d",
            phase_label,
            returncode,
            len(stdout.splitlines()),
            len(filtered_stderr),
        )
        if filtered_stderr:
            logger.warning(
                "nuclei [%s] stderr: %s",
                phase_label,
                filtered_stderr[:2000],
            )

        errors: list[str] = []
        findings: list[Finding] = []

        has_fatal = (
            "FTL" in filtered_stderr or "no templates provided" in filtered_stderr
        )
        if returncode > 1 or (returncode != 0 and has_fatal):
            err_detail = filtered_stderr or stdout.strip()
            errors.append(
                f"nuclei [{phase_label}] exited with "
                f"code {returncode}: {err_detail[:500]}"
            )
        elif stdout.strip():
            findings = self.parse_results(stdout)

        return findings, errors, stdout

    def _resolve_targeted_selection(
        self,
        context: ScanContext,
        has_explicit: bool,
    ) -> tuple[list[str], list[str], list[str]]:
        """Determine template dirs, tags, and workflows for Phase 2.

        When the user has set explicit ``template_dirs`` or ``tags``, those
        are returned as-is.  Otherwise the method builds a targeted
        selection from the detected technologies in *context*.

        Returns:
            A tuple of (template_dirs, extra_tags, workflow_paths).
        """
        if has_explicit:
            return (
                list(self.options.get("template_dirs", [])),
                list(self.options.get("tags", [])),
                [],
            )

        # Start with the default scan directories
        template_dirs = list(DEFAULT_TEMPLATE_DIRS)

        # Derive technology-specific tags and workflows
        extra_tags: list[str] = []
        workflows: list[str] = []
        seen_tags: set[str] = set()

        for tech in context.detected_technologies:
            tech_lower = tech.lower()
            for key, tag_list in TECH_TAG_MAP.items():
                if key in tech_lower:
                    for tag in tag_list:
                        if tag not in seen_tags:
                            extra_tags.append(tag)
                            seen_tags.add(tag)

            # Check for matching workflow
            for key, workflow_path in TECH_WORKFLOW_MAP.items():
                if key in tech_lower and workflow_path not in workflows:
                    workflows.append(workflow_path)

        if extra_tags:
            logger.info(
                "Nuclei Phase 2: tech-derived tags: %s",
                ", ".join(extra_tags[:20]),
            )
        if workflows:
            logger.info(
                "Nuclei Phase 2: tech-derived workflows: %s",
                ", ".join(workflows[:10]),
            )

        return template_dirs, extra_tags, workflows

    # Generic Nuclei classification tags that are NOT technology names.
    # These appear in info.tags and must be excluded from tech extraction.
    _NUCLEI_META_TAGS: frozenset[str] = frozenset(
        {
            "tech",
            "waf",
            "misc",
            "discovery",
            "cms",
            "detect",
            "panel",
            "exposure",
            "osint",
            "recon",
            "token",
            "cloud",
            "network",
            "dns",
            "fuzz",
            "headless",
            "file",
            "iot",
        }
    )

    @staticmethod
    def _extract_technologies(findings: list[Finding]) -> list[str]:
        """Extract technology names from Phase 1 fingerprinting findings.

        Nuclei technology detection templates use ``matcher-name`` to
        report the detected technology (e.g. ``nginx``, ``wordpress``).
        For metatag/CMS detection templates that lack a matcher-name,
        the ``extracted-results`` field contains the actual tech name.
        """
        techs: list[str] = []
        seen: set[str] = set()

        for finding in findings:
            raw = finding.raw_data or {}

            # matcher-name is the primary tech identifier
            matcher = raw.get("matcher-name", "")
            if matcher and matcher.lower() not in seen:
                techs.append(matcher.lower())
                seen.add(matcher.lower())

            # For metatag-cms and similar: extract tech from extracted-results
            extracted = raw.get("extracted-results", [])
            if isinstance(extracted, list):
                for val in extracted:
                    if isinstance(val, str) and val.strip():
                        # First word as tech name
                        # e.g. "Astro v5.15.9" -> "astro"
                        tech_name = val.split()[0].lower().rstrip(",;:")
                        if tech_name and tech_name not in seen:
                            techs.append(tech_name)
                            seen.add(tech_name)

            # Check nuclei tags, but filter out generic metadata tags
            for tag in raw.get("nuclei-tags", []):
                tag_lower = tag.lower()
                if (
                    tag_lower not in seen
                    and tag_lower not in NucleiScanner._NUCLEI_META_TAGS
                ):
                    techs.append(tag_lower)
                    seen.add(tag_lower)

        return techs

    @staticmethod
    def _build_url_list(
        target: Target,
        context: ScanContext,
    ) -> list[str]:
        """Build a list of URLs for Nuclei to scan.

        Combines the base target URL with any URLs discovered by
        earlier crawling scanners (e.g. Wapiti).  Returns an empty
        list when there are no extra URLs (caller will use ``-u``).
        """
        if not context.discovered_urls:
            return []

        # De-duplicate and ensure base URL is included
        urls: list[str] = [target.base_url]
        seen = {target.base_url}
        for url in context.discovered_urls:
            if url not in seen and url.startswith("http"):
                urls.append(url)
                seen.add(url)

        # Only use URL list if we have more than just the base URL
        if len(urls) <= 1:
            return []

        # Cap to avoid overwhelming nuclei
        return urls[:500]

    def _build_command(
        self,
        target: Target,
        *,
        template_dirs: list[str] | None = None,
        extra_tags: list[str] | None = None,
        workflows: list[str] | None = None,
        url_list: list[str] | None = None,
    ) -> list[str]:
        """Construct the nuclei CLI command list.

        Args:
            target: Scan target providing the URL and auth headers.
            template_dirs: Override template directories for this invocation.
            extra_tags: Additional tags to include beyond user-configured ones.
            workflows: Workflow YAML paths to run.
            url_list: URLs to scan (uses temp file with ``-list``).

        Returns:
            A list of strings suitable for
            :meth:`~core.scanner.BaseScanner._run_command`.
        """
        cmd = [
            "nuclei",
            "-jsonl",
            "-duc",
            "-silent",
            "-no-color",
            "-system-resolvers",
            "-tls-impersonate",
            "-fhr",
            "-retries",
            "2",
            "-nmhe",
            "-rate-limit",
            str(self.options["rate_limit"]),
            "-c",
            str(self.options["concurrency"]),
            "-bs",
            str(self.options["bulk_size"]),
            "-timeout",
            str(self.options.get("timeout_per_request", 30)),
        ]

        # Interactsh: enable OOB detection only when explicitly opted in
        if not self.options.get("enable_interactsh"):
            cmd.append("-no-interactsh")

        # Target: URL list file or single URL
        if url_list and len(url_list) > 1:
            url_file = self._write_url_list(url_list)
            cmd.extend(["-list", url_file])
        else:
            cmd.extend(["-u", target.base_url])

        # Template selection
        has_template_selection = False
        effective_dirs = template_dirs if template_dirs is not None else []
        user_template_dirs = self.options.get("template_dirs", [])

        # User-configured template_dirs override everything
        if user_template_dirs:
            for tdir in user_template_dirs:
                cmd.extend(["-t", tdir])
                has_template_selection = True
        else:
            # Use phase-specific template dirs
            for tdir in effective_dirs:
                cmd.extend(["-t", tdir])
                has_template_selection = True

            # TemplateManager paths (external repos)
            if not effective_dirs:
                for template_path in self.options.get("templates", []):
                    cmd.extend(["-t", template_path])
                    has_template_selection = True

        # Workflows
        for workflow_path in workflows or []:
            cmd.extend(["-w", workflow_path])
            has_template_selection = True

        # Tags: merge user-configured + tech-derived
        all_tags: list[str] = list(self.options.get("tags", []))
        if extra_tags:
            seen = set(t.lower() for t in all_tags)
            for tag in extra_tags:
                if tag.lower() not in seen:
                    all_tags.append(tag)
                    seen.add(tag.lower())

        if all_tags:
            cmd.extend(["-tags", ",".join(all_tags)])
            has_template_selection = True

        # Fallback: if nothing selected, use defaults
        if not has_template_selection:
            for tdir in DEFAULT_TEMPLATE_DIRS:
                cmd.extend(["-t", tdir])

        # Severity filter
        if self.options.get("severity"):
            cmd.extend(["-severity", ",".join(self.options["severity"])])

        # Exclude tags (always exclude dos for safety)
        exclude_tags = list(self.options.get("exclude_tags", []))
        if "dos" not in [t.lower() for t in exclude_tags]:
            exclude_tags.append("dos")
        cmd.extend(["-etags", ",".join(exclude_tags)])

        # Forward auth headers
        auth_headers = target.auth.as_headers()
        for header_name, header_value in auth_headers.items():
            cmd.extend(["-H", f"{header_name}: {header_value}"])

        # Extra args
        cmd.extend(self.options.get("extra_args", []))

        return cmd

    @staticmethod
    def _write_url_list(urls: list[str]) -> str:
        """Write URLs to a temp file for Nuclei's ``-list`` flag.

        Returns:
            Path to the temporary file. The file will be cleaned up
            by the OS (using ``delete=False`` in a temp directory).
        """
        with tempfile.NamedTemporaryFile(
            mode="w",
            suffix=".txt",
            prefix="nuclei_urls_",
            delete=False,
        ) as tmp:
            tmp.write("\n".join(urls))
            return tmp.name

    @staticmethod
    def _generic_remediation(tags: list[str], severity: Severity) -> str:
        """Return a generic remediation hint based on assigned tags.

        Args:
            tags: OWASP tags assigned to the finding.
            severity: Finding severity level.

        Returns:
            A plain-text remediation recommendation string.
        """
        remediation_map = {
            "sql_injection": (
                "Use parameterised queries or prepared statements.  Never "
                "interpolate user-controlled data directly into SQL strings."
            ),
            "xss": (
                "Apply context-sensitive output encoding and enforce a strict "
                "Content-Security-Policy header."
            ),
            "command_injection": (
                "Avoid passing user-supplied input to shell commands.  Use "
                "safe APIs that do not invoke a shell interpreter."
            ),
            "ssrf": (
                "Validate and allowlist server-side request destinations.  "
                "Block access to internal network ranges from outbound requests."
            ),
            "outdated_component": (
                "Update the affected component to the latest patched version.  "
                "Subscribe to vendor security advisories."
            ),
            "default_credentials": (
                "Change default usernames and passwords before deploying to "
                "production.  Enforce strong credential policies."
            ),
            "exposed_panel": (
                "Restrict access to administrative interfaces via IP allowlisting "
                "or VPN.  Do not expose management panels to the public internet."
            ),
            "sensitive_data_exposure": (
                "Remove or restrict access to the exposed resource.  Ensure "
                "sensitive data is not stored in publicly accessible locations."
            ),
            "missing_security_headers": (
                "Add the recommended HTTP security headers "
                "(Strict-Transport-Security, Content-Security-Policy, "
                "X-Content-Type-Options, X-Frame-Options)."
            ),
            "directory_listing": (
                "Disable directory indexing in the web server configuration."
            ),
            "weak_tls": (
                "Disable deprecated TLS/SSL protocol versions and weak cipher "
                "suites.  Enable TLS 1.2 and TLS 1.3 only."
            ),
        }

        for tag in tags:
            if tag in remediation_map:
                return remediation_map[tag]

        return (
            "Review the identified issue against the relevant security standard "
            "and apply vendor-recommended hardening guidance."
        )
