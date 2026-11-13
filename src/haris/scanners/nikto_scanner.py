import json
import logging
import re
import tempfile
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from ..core.decorators import handle_scanner_errors
from ..data.scanner_config import (
    get_nikto_keyword_rules,
    get_nikto_osvdb_critical,
    get_nikto_severity_map,
)
from ..models import Confidence, Finding, ScannerResult, Severity, Target
from .base import ExternalToolScanner, compact_number

logger = logging.getLogger(__name__)

# Nikto appends the format extension to the -output name.
REPORT_STEM = "nikto_report"
REPORT_NAME = f"{REPORT_STEM}.json"
DEFAULT_SCHEME = "http"
# Nikto overran its own -maxtime by 35 s; the margin lets it write its report.
MAXTIME_MARGIN_S = 60
INTERESTING_PATH_CLASS = "unclassified:nikto:interesting_path"
# Nikto 2.6 reports the bare message; older reports prefix it with the path.
INTERESTING_PATH = re.compile(r"(?:/\S*: )?This might be interesting")

type KeywordRule = tuple[re.Pattern[str], list[str], Severity]


def _build_severity_map() -> dict[str, Severity]:
    raw = get_nikto_severity_map()
    return {k: Severity[v] for k, v in raw.items()}


def _keyword_pattern(keywords: list[str]) -> re.Pattern[str]:
    """Match keywords as whole words so 'options' skips X-Frame-Options."""
    parts = []
    for kw in keywords:
        before = r"(?<![A-Za-z0-9_-])" if kw[0].isalnum() else ""
        after = r"(?![A-Za-z0-9_])" if kw[-1].isalnum() else ""
        parts.append(f"{before}{re.escape(kw.lower())}{after}")
    return re.compile("|".join(parts))


def _build_keyword_rules() -> list[KeywordRule]:
    return [
        (
            _keyword_pattern(rule["keywords"]),
            rule["tags"],
            Severity[rule["severity"]],
        )
        for rule in get_nikto_keyword_rules()
    ]


_severity_map: dict[str, Severity] | None = None
_keyword_rules: list[KeywordRule] | None = None
_osvdb_critical: frozenset[str] | None = None


def _get_severity_map() -> dict[str, Severity]:
    global _severity_map
    if _severity_map is None:
        _severity_map = _build_severity_map()
    return _severity_map


def _get_keyword_rules() -> list[KeywordRule]:
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
    """Return OWASP tags and severity for a Nikto message."""
    msg_lower = msg.lower()

    for pattern, tags, severity in _get_keyword_rules():
        if pattern.search(msg_lower):
            if osvdb_id and osvdb_id != "0" and osvdb_id in _get_osvdb_critical():
                severity = Severity.CRITICAL
            return tags, severity

    return ["security_misconfiguration"], Severity.INFO


class NiktoScanner(ExternalToolScanner):
    """Adapter for the Nikto web server scanner (2.6 JSON report).

    Options: ``timeout`` (seconds, default 300; nikto gets ``-maxtime`` 60 s below it
    unless ``extra_args`` sets one), ``tuning`` (nikto ``-Tuning`` string, default
    nikto's own), ``extra_args`` (allow-listed flags only).
    """

    name = "nikto"
    binds_to = "egress_proxy"
    version = "2.x"
    description = "Web server misconfiguration and outdated software scanner"

    def __init__(self, options: dict[str, Any] | None = None) -> None:
        super().__init__(options)
        self.options.setdefault("timeout", 300)
        self.options.setdefault("extra_args", [])
        self.options.setdefault("tuning", "")

    @handle_scanner_errors
    def scan(self, target: Target, context: Any = None) -> ScannerResult:
        if (refusal := self._unbound(target, context)) is not None:
            return refusal
        if not self._check_tool_available("nikto"):
            return ScannerResult(
                scanner_name=self.name,
                errors=["nikto is not installed or not on PATH"],
            )
        self._begin(target, context)

        with tempfile.TemporaryDirectory() as tmpdir:
            cmd = self._build_command(target, str(Path(tmpdir) / REPORT_STEM))
            timeout = self.options["timeout"]
            run = self._run_to_file(cmd, Path(tmpdir) / REPORT_NAME, timeout)

        result = ScannerResult(scanner_name=self.name, raw_output=self._redact(run.raw))
        if run.timed_out:
            result.errors.append(self._timeout_error(timeout))
        # Nikto exits 1 when it finds issues; only no report at all is an error.
        elif run.returncode not in (0, 1) and not run.raw:
            result.errors.append(
                f"nikto exited with code {run.returncode}: "
                f"{self._redact(run.stderr)[:500]}"
            )
        if run.raw:
            result.findings = self.parse_results(run.raw, base_url=target.base_url)
        return result

    def parse_results(
        self, raw_output: str, base_url: str | None = None
    ) -> list[Finding]:
        """Parse a Nikto JSON report; *base_url* supplies the scheme (default http)."""
        findings: list[Finding] = []

        try:
            data = json.loads(raw_output)
        except json.JSONDecodeError as exc:
            logger.error("Failed to parse Nikto JSON output: %s", exc)
            return findings

        scheme = urlparse(base_url).scheme if base_url else DEFAULT_SCHEME
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
            target_port = str(host_entry.get("port", ""))
            root = f"{scheme}://{target_host}" + (
                f":{target_port}" if target_port else ""
            )

            for vuln in vulnerabilities:
                if not isinstance(vuln, dict) or not vuln.get("msg"):
                    continue
                findings.append(self._vuln_to_finding(vuln, root))

        return findings

    def _vuln_to_finding(self, vuln: dict[str, Any], root: str) -> Finding:
        msg: str = vuln["msg"]
        url_path: str = vuln.get("url", "/")
        # Nikto 2.6 reports "id"; older releases reported "osvdbid".
        test_id = str(vuln.get("osvdbid") or vuln.get("id") or "0")
        # Checked first: keyword rules would rate "/debug/: ..." as MEDIUM.
        interesting = INTERESTING_PATH.match(msg) is not None
        tags, severity = (
            (["security_misconfiguration"], Severity.INFO)
            if interesting
            else _classify_finding(msg, test_id)
        )

        references = [
            ref
            for ref in (vuln.get("references"), vuln.get("osvdblink"))
            if isinstance(ref, str) and ref
        ]
        return Finding(
            title=msg[:120],
            description=msg,
            severity=severity,
            confidence=Confidence.FIRM,
            url=f"{root}{url_path}" if url_path.startswith("/") else url_path,
            method=vuln.get("method", "GET"),
            evidence=f"Nikto test {test_id}" if test_id != "0" else "",
            remediation=self._build_remediation(tags, msg),
            references=references,
            scanner=self.name,
            vuln_class=INTERESTING_PATH_CLASS if interesting else "",
            tags=tags,
            raw_data=self._redact_data(vuln),
        )

    def _build_command(self, target: Target, output_path: str) -> list[str]:
        """Build the nikto argv; *output_path* has no extension (nikto adds .json)."""
        cmd = [
            "nikto",
            "-host",
            target.base_url,
            "-Format",
            "json",
            "-output",
            output_path,
            "-nointeractive",
            "-nocheck",
        ]

        tuning = self.options.get("tuning", "")
        if isinstance(tuning, list):
            tuning = "".join(tuning)
        if tuning:
            cmd.extend(["-Tuning", tuning])

        if self._proxy:
            cmd.extend(["-useproxy", self._proxy])

        for header_name, header_value in target.auth.as_headers().items():
            cmd.extend(["-Add-header", f"{header_name}: {header_value}"])

        extra_args = self._extra_args()
        maxtime = int(self.options["timeout"]) - MAXTIME_MARGIN_S
        if "-maxtime" not in extra_args and maxtime > 0:
            cmd.extend(["-maxtime", f"{maxtime}s"])
        cmd.extend(extra_args)
        if self._rate_rps > 0:
            # After extra_args so a user -Pause cannot lower the pause.
            cmd.extend(["-Pause", compact_number(1 / self._rate_rps)])
        return cmd

    @staticmethod
    def _build_remediation(tags: list[str], msg: str) -> str:  # noqa: ARG004
        """Return a remediation hint for the assigned tags."""
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
