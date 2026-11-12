import json
import logging
import tempfile
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from ..core.decorators import handle_scanner_errors, register_scanner
from ..data.scanner_config import (
    get_wapiti_category_tags,
    get_wapiti_excluded_modules,
    get_wapiti_severity_map,
)
from ..models import Confidence, Finding, ScannerResult, Severity, Target
from .base import ExternalToolScanner
from .wapiti_exclude import wapiti_exclude_urls
from .wapiti_session import session_report

logger = logging.getLogger(__name__)

DEFAULT_MODULES = "common"
FALLBACK_TAGS = ["security_misconfiguration"]
SESSION_DIRNAME = "session"
# Kill grace past --max-scan-time; a stuck module ignores that flag.
SCAN_KILL_GRACE_SECONDS = 60
_TIMEOUT_RECOVERED = (
    "wapiti timed out after %ds; %d findings recovered from its session database"
)
_TIMEOUT_EMPTY = "wapiti timed out after %ds; no findings recovered"
_TIMEOUT_REPORT = "wapiti timed out after %ds; its report was kept"
LOOPBACK_ENDPOINT = "http://127.0.0.1:9/"  # placeholder; nothing listens
# Unset external is LOOPBACK_ENDPOINT; unset internal is the target URL (startup ping).
ENDPOINT_FLAGS = {
    "external_endpoint": "--external-endpoint",
    "internal_endpoint": "--internal-endpoint",
}
CALLBACK_MODULES = ("ssrf", "xxe")  # blind; need both endpoints
# Log4Shell verifies over DNS, which a callback receiver cannot serve.
DNS_MODULE = "log4shell"
# Wapiti's usage banner and box-drawing logo are noise in stderr.
_BANNER_PREFIXES = ("usage:", "[", "██", "╔", "╗", "║", "╚", "╝", "╠", "╣")


def _build_severity_map() -> dict[int, Severity]:
    raw = get_wapiti_severity_map()
    return {k: Severity[v] for k, v in raw.items()}


_severity_map: dict[int, Severity] | None = None
_category_tags: dict[str, list[str]] | None = None


def _get_severity_map() -> dict[int, Severity]:
    global _severity_map
    if _severity_map is None:
        _severity_map = _build_severity_map()
    return _severity_map


def _get_category_tags() -> dict[str, list[str]]:
    global _category_tags
    if _category_tags is None:
        _category_tags = get_wapiti_category_tags()
    return _category_tags


def _timeout_message(timeout: int, findings: int, from_session: bool) -> str:
    if not from_session:
        return _TIMEOUT_REPORT % timeout
    if findings:
        return _TIMEOUT_RECOVERED % (timeout, findings)
    return _TIMEOUT_EMPTY % timeout


@register_scanner
class WapitiScanner(ExternalToolScanner):
    """Adapter for Wapiti 3.3.2.

    Requires ``wapiti3`` on PATH. Drops header, cookie, redirect and TLS
    modules, and ``information_disclosure`` until a live run shows the
    3.3.2 path regex is safe.
    """

    name = "wapiti"
    binds_to = "egress_proxy"
    version = "3.3"
    description = "Black-box web application vulnerability scanner"

    def __init__(self, options: dict[str, Any] | None = None) -> None:
        super().__init__(options)
        self.options.setdefault("timeout", 300)
        self.options.setdefault("max_scan_time", 600)
        self.options.setdefault("scope", "folder")
        self.options.setdefault("modules", "all")
        self.options.setdefault("max_links", 500)
        self.options.setdefault("extra_args", [])

    @handle_scanner_errors
    def scan(self, target: Target, context: Any = None) -> ScannerResult:
        if (refusal := self._unbound(target, context)) is not None:
            return refusal
        if not self._check_tool_available("wapiti"):
            return ScannerResult(
                scanner_name=self.name,
                errors=["wapiti3 is not installed or not on PATH"],
            )
        self._begin(target, context)

        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            output_file = root / "wapiti_report.json"
            session_dir = root / SESSION_DIRNAME
            session_dir.mkdir()
            cmd = self._build_command(target, str(output_file), str(session_dir))
            timeout = self.options["max_scan_time"] + SCAN_KILL_GRACE_SECONDS
            run = self._run_to_file(cmd, output_file, timeout)
            raw = run.raw
            from_session = not raw and (run.timed_out or run.returncode != 0)
            if from_session:
                raw = session_report(session_dir)

        result = ScannerResult(scanner_name=self.name, raw_output=self._redact(raw))
        findings = self.parse_results(raw) if raw else []
        if run.timed_out:
            result.errors.append(_timeout_message(timeout, len(findings), from_session))
        elif run.returncode != 0:
            err_lines = [
                line
                for line in self._redact(run.stderr).splitlines()
                if line.strip()
                and not line.strip().startswith(_BANNER_PREFIXES)
                and "wapiti [-h]" not in line
            ]
            err_msg = "\n".join(err_lines[:10]) or f"exit code {run.returncode}"
            result.errors.append(f"wapiti exited with code {run.returncode}: {err_msg}")

        result.findings = findings
        return result

    def _finding_from_vuln(self, category: str, vuln: dict[str, Any]) -> Finding:
        wstg = vuln.get("wstg", "")
        if isinstance(wstg, list):
            wstg = ", ".join(str(w) for w in wstg)
        info = str(vuln.get("info", "N/A"))
        return Finding(
            title=f"{category}: {info[:80]}",
            description=info,
            severity=_get_severity_map().get(vuln.get("level", 0), Severity.INFO),
            confidence=Confidence.FIRM,
            url=vuln.get("path", ""),
            parameter=vuln.get("parameter") or "",
            method=vuln.get("method", "GET"),
            evidence=info,
            request_example=self._redact(vuln.get("curl_command", "")),
            remediation=wstg,
            references=[
                ref
                for ref in (vuln.get("references") or {}).values()
                if isinstance(ref, str)
            ],
            scanner=self.name,
            tags=list(_get_category_tags().get(category, FALLBACK_TAGS)),
            raw_data=self._redact_data(vuln),
        )

    def parse_results(self, raw_output: str) -> list[Finding]:
        """Parse Wapiti JSON report into Finding objects."""
        findings: list[Finding] = []

        try:
            data = json.loads(raw_output)
        except json.JSONDecodeError as exc:
            logger.error("Failed to parse Wapiti JSON output: %s", exc)
            return findings

        for category, vulns in (data.get("vulnerabilities") or {}).items():
            if isinstance(vulns, list):
                findings.extend(self._finding_from_vuln(category, v) for v in vulns)

        # Anomalies (e.g. 500 errors triggered) are low-confidence findings.
        for category, items in (data.get("anomalies") or {}).items():
            if not isinstance(items, list):
                continue
            for item in items:
                findings.append(
                    Finding(
                        title=f"Anomaly ({category}): {item.get('info', '')[:80]}",
                        description=item.get("info", ""),
                        severity=Severity.LOW,
                        confidence=Confidence.TENTATIVE,
                        url=item.get("path", ""),
                        method=item.get("method", "GET"),
                        scanner=self.name,
                        tags=list(_get_category_tags().get(category, FALLBACK_TAGS)),
                        raw_data=self._redact_data(item),
                    )
                )

        return findings

    def _module_spec(self) -> str:
        modules = self.options.get("modules", DEFAULT_MODULES)
        if isinstance(modules, list):
            modules = ",".join(modules)
        # "all" predates Wapiti's own preset of that name; keep the default set.
        if modules in ("", "all"):
            modules = DEFAULT_MODULES
        names = [*get_wapiti_excluded_modules(), DNS_MODULE]
        if not all(self.options.get(option) for option in ENDPOINT_FLAGS):
            names.extend(CALLBACK_MODULES)
        return ",".join([modules, *(f"-{name}" for name in names)])

    def _endpoint_args(self, target: Target) -> list[str]:
        args: list[str] = []
        for option, flag in ENDPOINT_FLAGS.items():
            value = self.options.get(option)
            if not value:
                fallback = (
                    target.base_url
                    if option == "internal_endpoint"
                    else LOOPBACK_ENDPOINT
                )
                args.extend([flag, fallback])
                continue
            parts = urlsplit(str(value))
            if parts.scheme not in ("http", "https") or not parts.netloc:
                raise ValueError(f"{option} must be an http(s) URL, got {value!r}")
            args.extend([flag, str(value)])
        return args

    def _build_command(
        self, target: Target, output_path: str, session_dir: str
    ) -> list[str]:
        """Construct the wapiti argv."""
        cmd = [
            "wapiti",
            "--url",
            target.base_url,
            "--format",
            "json",
            "--output",
            output_path,
            "--scope",
            self.options["scope"],
            "--timeout",
            str(self.options["timeout"]),
            "--max-scan-time",
            str(self.options["max_scan_time"]),
            "--max-links-per-page",
            str(self.options["max_links"]),
            "--flush-session",
            "--store-session",
            session_dir,
            "--no-bugreport",
            "--module",
            self._module_spec(),
        ]

        if self._proxy:
            cmd.extend(["--proxy", self._proxy])

        for url in wapiti_exclude_urls(target.base_url, target.scope.excluded_paths):
            cmd.extend(["--exclude", url])

        for name, value in target.auth.as_headers().items():
            cmd.extend(["--header", f"{name}: {value}"])

        cmd.extend(self._endpoint_args(target))
        cmd.extend(self._extra_args())
        return cmd
