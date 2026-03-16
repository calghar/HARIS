import json
import logging
import tempfile
from pathlib import Path
from typing import Any

from ..core.decorators import register_scanner
from ..core.scanner import BaseScanner
from ..models import Confidence, Finding, ScannerResult, Severity, Target

logger = logging.getLogger(__name__)

# Map Wapiti severity levels to our internal model
_WAPITI_SEVERITY_MAP: dict[str, Severity] = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
    "info": Severity.INFO,
}

# Map Wapiti vulnerability categories to our OWASP tag keywords
_WAPITI_CATEGORY_TAGS: dict[str, list[str]] = {
    "SQL Injection": ["sql_injection"],
    "Blind SQL Injection": ["sql_injection"],
    "Cross Site Scripting": ["xss"],
    "CRLF Injection": ["crlf_injection"],
    "Commands execution": ["command_injection"],
    "File Handling": ["directory_traversal"],
    "XXE": ["xxe"],
    "SSRF": ["ssrf"],
    "Open Redirect": ["open_redirect"],
    "Content Security Policy Configuration": ["missing_security_headers"],
    "HTTP Secure Headers": ["missing_security_headers"],
    "HttpOnly Flag cookie": ["security_misconfiguration"],
    "Secure Flag cookie": ["security_misconfiguration"],
}


@register_scanner
class WapitiScanner(BaseScanner):
    """Adapter for the Wapiti web vulnerability scanner.

    Requires `wapiti3` to be installed and on PATH.
    Install: ``pip install wapiti3``
    """

    name = "wapiti"
    version = "3.x"
    description = "Black-box web application vulnerability scanner"

    def __init__(self, options: dict[str, Any] | None = None) -> None:
        super().__init__(options)
        self.options.setdefault("timeout", 300)
        self.options.setdefault("max_scan_time", 600)
        self.options.setdefault("scope", "folder")
        self.options.setdefault("modules", "all")
        # Rate limit: max concurrent connections
        self.options.setdefault("max_links", 500)

    def scan(self, target: Target) -> ScannerResult:
        if not self._check_tool_available("wapiti"):
            return ScannerResult(
                scanner_name=self.name,
                errors=["wapiti3 is not installed or not on PATH"],
            )

        with tempfile.TemporaryDirectory() as tmpdir:
            output_file = Path(tmpdir) / "wapiti_report.json"

            cmd = self._build_command(target, str(output_file))
            returncode, _, stderr = self._run_command(
                cmd, timeout=self.options["max_scan_time"] + 60
            )

            raw = ""
            if output_file.exists():
                raw = output_file.read_text()

            result = ScannerResult(
                scanner_name=self.name,
                raw_output=raw,
            )

            if returncode != 0:
                # Filter out the usage banner from error output
                err_lines = [
                    line for line in stderr.splitlines()
                    if line.strip()
                    and not line.strip().startswith((
                        "usage:", "[", "██",
                        "╔", "╗", "║", "╚", "╝", "╠", "╣",
                    ))
                    and "wapiti [-h]" not in line
                ]
                err_msg = (
                    "\n".join(err_lines[:10])
                    if err_lines
                    else f"exit code {returncode}"
                )
                result.errors.append(
                    f"wapiti exited with code {returncode}: {err_msg}"
                )

            if raw:
                result.findings = self.parse_results(raw)

            return result

    def parse_results(self, raw_output: str) -> list[Finding]:
        """Parse Wapiti JSON report into Finding objects."""
        findings: list[Finding] = []

        try:
            data = json.loads(raw_output)
        except json.JSONDecodeError as exc:
            logger.error("Failed to parse Wapiti JSON output: %s", exc)
            return findings

        vulnerabilities = data.get("vulnerabilities", {})
        for category_name, vulns in vulnerabilities.items():
            if not isinstance(vulns, list):
                continue

            tags = _WAPITI_CATEGORY_TAGS.get(category_name, [])

            for vuln in vulns:
                severity = _WAPITI_SEVERITY_MAP.get(
                    vuln.get("level", "info").lower(),
                    Severity.INFO,
                )

                finding = Finding(
                    title=f"{category_name}: {vuln.get('info', 'N/A')[:80]}",
                    description=vuln.get("info", ""),
                    severity=severity,
                    confidence=Confidence.FIRM,
                    url=vuln.get("path", ""),
                    parameter=vuln.get("parameter", ""),
                    method=vuln.get("method", "GET"),
                    evidence=vuln.get("info", ""),
                    request_example=vuln.get("curl_command", ""),
                    remediation=vuln.get("wstg", ""),
                    references=[
                        ref
                        for ref in vuln.get("references", {}).values()
                        if isinstance(ref, str)
                    ],
                    scanner=self.name,
                    tags=tags,
                    raw_data=vuln,
                )
                findings.append(finding)

        # Also capture "anomalies" (e.g. 500 errors triggered)
        anomalies = data.get("anomalies", {})
        for category_name, items in anomalies.items():
            if not isinstance(items, list):
                continue
            for item in items:
                finding = Finding(
                    title=f"Anomaly ({category_name}): {item.get('info', '')[:80]}",
                    description=item.get("info", ""),
                    severity=Severity.LOW,
                    confidence=Confidence.TENTATIVE,
                    url=item.get("path", ""),
                    method=item.get("method", "GET"),
                    scanner=self.name,
                    tags=["security_misconfiguration"],
                    raw_data=item,
                )
                findings.append(finding)

        return findings

    def _build_command(self, target: Target, output_path: str) -> list[str]:
        """Construct the wapiti CLI command."""
        cmd = [
            "wapiti",
            "--url", target.base_url,
            "--format", "json",
            "--output", output_path,
            "--scope", self.options["scope"],
            "--timeout", str(self.options["timeout"]),
            "--max-scan-time", str(self.options["max_scan_time"]),
            "--max-links-per-page", str(self.options["max_links"]),
            "--flush-session",
        ]

        # Module selection
        modules = self.options.get("modules", "all")
        if modules != "all":
            cmd.extend(["--module", modules])

        # Excluded paths from target scope
        for path in target.scope.excluded_paths:
            cmd.extend(["--exclude", path])

        # Auth headers
        auth_headers = target.auth.as_headers()
        for name, value in auth_headers.items():
            cmd.extend(["--header", f"{name}: {value}"])

        # Colour off for parseable output
        cmd.append("--no-bugreport")

        return cmd
