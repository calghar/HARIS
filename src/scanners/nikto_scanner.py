import json
import logging
import tempfile
from pathlib import Path
from typing import Any

from ..core.decorators import handle_scanner_errors, register_scanner
from ..core.scanner import BaseScanner
from ..data.scanner_config import (
    get_nikto_keyword_rules,
    get_nikto_osvdb_critical,
    get_nikto_severity_map,
)
from ..models import Confidence, Finding, ScannerResult, Severity, Target

logger = logging.getLogger(__name__)


def _build_severity_map() -> dict[str, Severity]:
    raw = get_nikto_severity_map()
    return {k: Severity[v] for k, v in raw.items()}


def _build_keyword_rules() -> list[tuple[list[str], list[str], Severity]]:
    raw_rules = get_nikto_keyword_rules()
    return [
        (rule["keywords"], rule["tags"], Severity[rule["severity"]])
        for rule in raw_rules
    ]


_severity_map: dict[str, Severity] | None = None
_keyword_rules: list[tuple[list[str], list[str], Severity]] | None = None
_osvdb_critical: frozenset[str] | None = None


def _get_severity_map() -> dict[str, Severity]:
    global _severity_map
    if _severity_map is None:
        _severity_map = _build_severity_map()
    return _severity_map


def _get_keyword_rules() -> list[tuple[list[str], list[str], Severity]]:
    global _keyword_rules
    if _keyword_rules is None:
        _keyword_rules = _build_keyword_rules()
    return _keyword_rules


def _get_osvdb_critical() -> frozenset[str]:
    global _osvdb_critical
    if _osvdb_critical is None:
        _osvdb_critical = get_nikto_osvdb_critical()
    return _osvdb_critical


def _classify_finding(msg: str, osvdb_id: str) -> tuple[list[str], Severity]:
    """Determine OWASP tags and severity for a Nikto finding.

    Args:
        msg: The human-readable message from Nikto's JSON output.
        osvdb_id: The OSVDB ID string (may be empty or "0").

    Returns:
        A tuple of (tags, severity).
    """
    msg_lower = msg.lower()

    for keywords, tags, severity in _get_keyword_rules():
        if any(kw in msg_lower for kw in keywords):
            # Escalate to CRITICAL for known critical OSVDB entries.
            if osvdb_id and osvdb_id != "0" and osvdb_id in _get_osvdb_critical():
                severity = Severity.CRITICAL
            return tags, severity

    # No rule matched — treat as informational misconfiguration.
    return ["security_misconfiguration"], Severity.INFO


@register_scanner
class NiktoScanner(BaseScanner):
    """Adapter for the Nikto web server scanner.

    Invokes ``nikto`` as a subprocess, writes JSON output to a temporary
    file, then parses each finding into a :class:`~core.finding.Finding`.

    Requires ``nikto`` to be installed and on PATH.
    Install: see https://github.com/sullo/nikto

    Options (pass via constructor or :meth:`configure`):

    ``timeout`` (int, default 300)
        Maximum seconds to wait for nikto to complete.
    ``extra_args`` (list[str], default [])
        Additional CLI flags appended verbatim to the nikto command.
    ``tuning`` (str, default "")
        Nikto tuning option controlling which tests to run
        (e.g. ``"1234"`` for file/cgi/misconfiguration/index tests).
        Empty string means nikto uses its own defaults.

    Example::

        scanner = NiktoScanner(options={"tuning": "123b"})
        result = scanner.scan(target)
    """

    name = "nikto"
    version = "2.x"
    description = "Web server misconfiguration and outdated software scanner"

    def __init__(self, options: dict[str, Any] | None = None) -> None:
        super().__init__(options)
        self.options.setdefault("timeout", 300)
        self.options.setdefault("extra_args", [])
        # Tuning: "" = nikto default, "123b" = files+CGI+misc+outdated
        self.options.setdefault("tuning", "")

    @handle_scanner_errors
    def scan(self, target: Target, context: Any = None) -> ScannerResult:  # noqa: ARG002
        """Run Nikto against *target* and return parsed findings.

        The method shells out to the ``nikto`` binary, captures JSON output
        written to a temporary file, and delegates to :meth:`parse_results`.

        Args:
            target: The :class:`~core.target.Target` to scan.  Only the
                ``base_url`` and auth headers are used.

        Returns:
            A :class:`~core.scanner.ScannerResult` containing findings and
            any errors encountered during the scan.
        """
        if not self._check_tool_available("nikto"):
            return ScannerResult(
                scanner_name=self.name,
                errors=["nikto is not installed or not on PATH"],
            )

        with tempfile.TemporaryDirectory() as tmpdir:
            output_file = Path(tmpdir) / "nikto_report.json"

            cmd = self._build_command(target, str(output_file))
            returncode, _, stderr = self._run_command(
                cmd, timeout=self.options["timeout"]
            )

            raw = ""
            if output_file.exists():
                raw = output_file.read_text()

            result = ScannerResult(
                scanner_name=self.name,
                raw_output=raw,
            )

            # Nikto exits non-zero when it finds vulnerabilities (exit code 1).
            # Only treat it as an error when there is also no output file.
            if returncode not in (0, 1) and not raw:
                result.errors.append(
                    f"nikto exited with code {returncode}: {stderr[:500]}"
                )

            if raw:
                result.findings = self.parse_results(raw)

            return result

    def parse_results(self, raw_output: str) -> list[Finding]:
        """Parse Nikto JSON output into :class:`~core.finding.Finding` objects.

        Nikto's JSON structure wraps results under a top-level ``"vulnerabilities"``
        list (when using ``-Format json``).  Each entry has at minimum:

        - ``"msg"``: human-readable description
        - ``"url"``: the path that triggered the finding
        - ``"method"``: HTTP method used
        - ``"osvdbid"``: OSVDB identifier (may be ``"0"`` when unknown)
        - ``"osvdblink"``: URL to the OSVDB entry

        Args:
            raw_output: Raw JSON string produced by ``nikto -Format json``.

        Returns:
            List of :class:`~core.finding.Finding` objects.  Returns an empty
            list if parsing fails, logging the error at ERROR level.
        """
        findings: list[Finding] = []

        try:
            data = json.loads(raw_output)
        except json.JSONDecodeError as exc:
            logger.error("Failed to parse Nikto JSON output: %s", exc)
            return findings

        # Nikto may wrap results at the top level or inside a "vulnerabilities"
        # key depending on the version.  Handle both layouts.
        host_entries = data if isinstance(data, list) else [data]

        for host_entry in host_entries:
            vulnerabilities = host_entry.get("vulnerabilities", [])
            if not isinstance(vulnerabilities, list):
                logger.warning(
                    "Unexpected Nikto JSON shape; 'vulnerabilities' is not a list"
                )
                continue

            target_ip = host_entry.get("ip", "")
            target_host = host_entry.get("host", target_ip)
            target_port = str(host_entry.get("port", "80"))
            base_url = f"http://{target_host}:{target_port}"

            for vuln in vulnerabilities:
                if not isinstance(vuln, dict):
                    continue

                msg: str = vuln.get("msg", "")
                url_path: str = vuln.get("url", "/")
                method: str = vuln.get("method", "GET")
                osvdb_id: str = str(vuln.get("osvdbid", "0"))
                osvdb_link: str = vuln.get("osvdblink", "")

                if not msg:
                    continue

                if url_path.startswith("/"):
                    full_url = f"{base_url}{url_path}"
                else:
                    full_url = url_path
                tags, severity = _classify_finding(msg, osvdb_id)

                references: list[str] = []
                if osvdb_link:
                    references.append(osvdb_link)

                finding = Finding(
                    title=msg[:120],
                    description=msg,
                    severity=severity,
                    confidence=Confidence.FIRM,
                    url=full_url,
                    method=method,
                    evidence=f"OSVDB-{osvdb_id}" if osvdb_id != "0" else "",
                    remediation=self._build_remediation(tags, msg),
                    references=references,
                    scanner=self.name,
                    tags=tags,
                    raw_data=vuln,
                )
                findings.append(finding)

        return findings

    # Private helpers

    def _build_command(self, target: Target, output_path: str) -> list[str]:
        """Construct the nikto CLI command list.

        Args:
            target: Scan target providing the URL and auth headers.
            output_path: Absolute path where nikto should write JSON output.

        Returns:
            A list of strings suitable for
            :meth:`~core.scanner.BaseScanner._run_command`.
        """
        cmd = [
            "nikto",
            "-host",
            target.base_url,
            "-Format",
            "json",
            "-output",
            output_path,
            # Disable interactive prompts and colour codes.
            "-nointeractive",
        ]

        # Apply tuning filter if configured.
        tuning = self.options.get("tuning", "")
        if isinstance(tuning, list):
            tuning = "".join(tuning)
        if tuning:
            cmd.extend(["-Tuning", tuning])

        # Forward auth headers to nikto.
        auth_headers = target.auth.as_headers()
        for header_name, header_value in auth_headers.items():
            cmd.extend(["-useragent-extra", f"{header_name}: {header_value}"])

        # Append any caller-supplied extra flags.
        cmd.extend(self.options.get("extra_args", []))

        return cmd

    @staticmethod
    def _build_remediation(tags: list[str], msg: str) -> str:
        """Return a context-appropriate remediation hint.

        Args:
            tags: OWASP tags assigned to the finding.
            msg: The original Nikto message text.

        Returns:
            A plain-text remediation recommendation string.
        """
        if "outdated_server" in tags or "outdated_component" in tags:
            return (
                "Update the server software to the latest stable release. "
                "Subscribe to vendor security advisories to receive timely "
                "patch notifications."
            )
        if "directory_listing" in tags:
            return (
                "Disable directory indexing in the web server configuration "
                "(e.g. 'Options -Indexes' for Apache, 'autoindex off' for Nginx)."
            )
        if "security_misconfiguration" in tags:
            return (
                "Review the server configuration to remove or restrict access "
                "to the identified resource.  Apply the principle of least "
                "privilege and ensure only required HTTP methods are enabled."
            )
        return (
            "Review the identified issue and apply the vendor-recommended "
            "hardening guidance."
        )
