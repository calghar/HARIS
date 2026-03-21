"""Nuclei scanner adapter.

Nuclei is a fast, template-based vulnerability scanner from ProjectDiscovery.
Templates cover a broad surface area including:

- CVEs (network and HTTP-based)
- Exposed administrative panels and login pages
- Default credentials
- Misconfigurations (cloud, web, network)
- Exposed files and sensitive data disclosure
- DNS misconfigurations
- Technology fingerprinting

Each template has an associated severity (info/low/medium/high/critical) and
can carry arbitrary classification tags, CVE IDs, and CVSS scores in its
metadata, which are all included in the JSONL output this adapter consumes.

Homepage: https://github.com/projectdiscovery/nuclei
"""

import json
import logging
from typing import Any

from ..core.decorators import handle_scanner_errors, register_scanner
from ..core.scanner import BaseScanner
from ..models import Confidence, Finding, ScannerResult, Severity, Target

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

    Invokes ``nuclei`` as a subprocess with JSON-Lines (``-jsonl``) output,
    then parses each result line into a :class:`~core.finding.Finding`.

    Requires ``nuclei`` to be installed and on PATH.
    Install: ``go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest``
    or download a pre-built binary from https://github.com/projectdiscovery/nuclei/releases

    Options (pass via constructor or :meth:`configure`):

    ``timeout`` (int, default 600)
        Maximum seconds to wait for the nuclei run to complete.
    ``templates`` (list[str], default [])
        Explicit template paths or directories to run.  When empty, nuclei
        uses its default installed template set.
    ``tags`` (list[str], default [])
        Only run templates whose ``tags`` field contains one of these values
        (maps to nuclei ``-tags`` flag).
    ``severity`` (list[str], default [])
        Restrict output to specific severity levels, e.g. ``["high", "critical"]``
        (maps to nuclei ``-severity`` flag).
    ``rate_limit`` (int, default 150)
        Maximum HTTP requests per second sent to the target
        (maps to nuclei ``-rate-limit`` flag).
    ``extra_args`` (list[str], default [])
        Additional CLI flags appended verbatim to the nuclei command.

    Example::

        scanner = NucleiScanner(options={
            "severity": ["high", "critical"],
            "tags": ["cve", "misconfig"],
        })
        result = scanner.scan(target)
    """

    name = "nuclei"
    version = "3.x"
    description = "Template-based CVE, misconfiguration, and exposure scanner"

    def __init__(self, options: dict[str, Any] | None = None) -> None:
        super().__init__(options)
        self.options.setdefault("timeout", 600)
        self.options.setdefault("templates", [])
        self.options.setdefault("tags", [])
        self.options.setdefault("severity", [])
        self.options.setdefault("rate_limit", 150)
        self.options.setdefault("extra_args", [])

    @handle_scanner_errors
    def scan(self, target: Target) -> ScannerResult:
        """Run Nuclei against *target* and return parsed findings.

        Nuclei is invoked with ``-jsonl`` so each output line is a
        self-contained JSON object.  The method collects all output on stdout
        (no intermediate file needed) and passes it to :meth:`parse_results`.

        Args:
            target: The :class:`~core.target.Target` to scan.

        Returns:
            A :class:`~core.scanner.ScannerResult` containing findings and
            any errors encountered during the scan.
        """
        if not self._check_tool_available("nuclei"):
            return ScannerResult(
                scanner_name=self.name,
                errors=["nuclei is not installed or not on PATH"],
            )

        cmd = self._build_command(target)
        returncode, stdout, stderr = self._run_command(
            cmd, timeout=self.options["timeout"]
        )

        result = ScannerResult(
            scanner_name=self.name,
            raw_output=stdout,
        )

        # Nuclei exits 0 when no findings, 1 when findings were emitted,
        # and >1 on genuine errors.
        if returncode > 1 and not stdout.strip():
            result.errors.append(
                f"nuclei exited with code {returncode}: {stderr[:500]}"
            )

        if stdout.strip():
            result.findings = self.parse_results(stdout)

        return result

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

    def _build_command(self, target: Target) -> list[str]:
        """Construct the nuclei CLI command list.

        Args:
            target: Scan target providing the URL and auth headers.

        Returns:
            A list of strings suitable for
            :meth:`~core.scanner.BaseScanner._run_command`.
        """
        cmd = [
            "nuclei",
            "-u",
            target.base_url,
            # JSONL output so we can stream-parse line by line.
            "-jsonl",
            # Rate limiting to respect scope constraints.
            "-rate-limit",
            str(self.options["rate_limit"]),
            # Disable automatic updates during a scan run.
            "-no-update-templates",
            # Suppress progress bar / ANSI codes for clean stdout.
            "-silent",
        ]

        # Template selection: explicit paths take precedence over tag filters.
        for template_path in self.options.get("templates", []):
            cmd.extend(["-t", template_path])

        # Tag filter: run only templates with matching tags.
        if self.options.get("tags"):
            cmd.extend(["-tags", ",".join(self.options["tags"])])

        # Severity filter: limit to the specified levels.
        if self.options.get("severity"):
            cmd.extend(["-severity", ",".join(self.options["severity"])])

        # Forward auth headers to nuclei via -H flags.
        auth_headers = target.auth.as_headers()
        for header_name, header_value in auth_headers.items():
            cmd.extend(["-H", f"{header_name}: {header_value}"])

        # Append any caller-supplied extra flags.
        cmd.extend(self.options.get("extra_args", []))

        return cmd

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
