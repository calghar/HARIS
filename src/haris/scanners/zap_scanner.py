import ipaddress
import json
import logging
import tempfile
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from ..core.decorators import handle_scanner_errors, register_scanner
from ..data.scanner_config import get_zap_config
from ..models import Confidence, Finding, ScanContext, ScannerResult, Severity, Target
from ..net.errors import ScopeViolation, SSRFBlocked, TransportError
from ..net.ssrf import system_resolver, vet_addresses
from .base import ExternalToolScanner
from .zap_plan import HOME_DIR, REPORT_FILE, build_plan, command, write_plan

logger = logging.getLogger(__name__)

# Documented launchers first (cmdline page). zaproxy and zap are package names.
LAUNCHERS = ("zap.sh", "zap.bat", "zaproxy", "zap")
DEFAULT_TIMEOUT = 1800
DEFAULT_SPIDER_MINUTES = 5
DEFAULT_PASSIVE_MINUTES = 2
DEFAULT_ACTIVE_MINUTES = 15
DEFAULT_THREADS = 1
DEFAULT_DELAY_MS = 0
DEFAULT_MAX_INSTANCES = 200
_PREFLIGHT_ERRORS = (ScopeViolation, SSRFBlocked, TransportError)

_severity_map: dict[str, Severity] | None = None
_confidence_map: dict[str, Confidence] | None = None


def _enum_map[E: (Severity, Confidence)](key: str, enum: type[E]) -> dict[str, E]:
    mapped: dict[str, E] = {}
    raw = get_zap_config().get(key, {})
    if not isinstance(raw, dict):
        return mapped
    for code, name in raw.items():
        try:
            mapped[str(code)] = enum[str(name)]
        except KeyError:
            logger.warning("Ignoring unknown ZAP %s value %s", key, name)
    return mapped


def _severities() -> dict[str, Severity]:
    global _severity_map
    if _severity_map is None:
        _severity_map = _enum_map("severity_map", Severity)
    return _severity_map


def _confidences() -> dict[str, Confidence]:
    global _confidence_map
    if _confidence_map is None:
        _confidence_map = _enum_map("confidence_map", Confidence)
    return _confidence_map


def _host_addresses(host: str, port: int) -> list[str]:
    try:
        ipaddress.ip_address(host)
    except ValueError:
        return system_resolver(host, port)
    return [host]


def _cwe(value: object) -> str:
    text = str(value or "").strip()
    if text.isdigit() and int(text) > 0:
        return f"CWE-{int(text)}"
    return ""


def _text(value: object) -> str:
    return str(value or "").strip()


@register_scanner
class ZapScanner(ExternalToolScanner):
    """Runs ZAP's Automation Framework and reads a traditional-json report.

    Options: ``timeout`` (seconds), ``spider_minutes``, ``passive_minutes``,
    ``active_minutes``, ``threads``, ``delay_ms``. At most ``max_instances``
    alert instances, from ``scanners/zap.yaml``. Disabled unless selected.
    """

    name = "zap"
    version = "2.16"
    description = "OWASP ZAP active and passive scan via the Automation Framework"

    def __init__(self, options: dict[str, Any] | None = None) -> None:
        super().__init__(options)
        cfg = get_zap_config()
        self.options.setdefault("timeout", DEFAULT_TIMEOUT)
        self.options.setdefault("spider_minutes", DEFAULT_SPIDER_MINUTES)
        self.options.setdefault("passive_minutes", DEFAULT_PASSIVE_MINUTES)
        self.options.setdefault("active_minutes", DEFAULT_ACTIVE_MINUTES)
        self.options.setdefault("threads", DEFAULT_THREADS)
        self.options.setdefault("delay_ms", DEFAULT_DELAY_MS)
        self.options.setdefault("extra_args", [])
        self.options.setdefault(
            "max_instances", int(cfg.get("max_instances", DEFAULT_MAX_INSTANCES))
        )

    @handle_scanner_errors
    def scan(self, target: Target, context: ScanContext | None = None) -> ScannerResult:
        launcher = self._launcher()
        if launcher is None:
            return ScannerResult(
                scanner_name=self.name,
                errors=[
                    "ZAP launcher not on PATH (checked " + ", ".join(LAUNCHERS) + ")"
                ],
            )
        try:
            self._preflight(target, context)
        except _PREFLIGHT_ERRORS as exc:
            return ScannerResult(scanner_name=self.name, errors=[str(exc)])
        self._begin(target)

        timeout = int(self.options["timeout"])
        with tempfile.TemporaryDirectory() as tmp:
            work = Path(tmp)
            plan_path = write_plan(work, self._plan(target, work, context))
            (work / HOME_DIR).mkdir()
            cmd = command(launcher, plan_path, work / HOME_DIR, self._extra_args())
            run = self._run_to_file(cmd, work / REPORT_FILE, timeout)

        result = ScannerResult(scanner_name=self.name, raw_output=self._redact(run.raw))
        if run.timed_out:
            result.errors.append(self._timeout_error(timeout))
        elif run.returncode not in (0, 1, 2) and not run.raw:
            result.errors.append(
                f"zap exited with code {run.returncode}: "
                f"{self._redact(run.stderr)[:500]}"
            )
        if run.raw:
            result.findings = self.parse_results(run.raw)
        return result

    def parse_results(self, raw_output: str) -> list[Finding]:
        """One finding per alert instance, stopped at ``max_instances``."""
        try:
            data = json.loads(raw_output)
        except json.JSONDecodeError as exc:
            logger.error("Failed to parse ZAP JSON: %s", exc)
            return []
        if not isinstance(data, dict):
            return []
        cap = int(self.options["max_instances"])
        findings: list[Finding] = []
        sites = data.get("site")
        if not isinstance(sites, list):
            return findings
        for site in sites:
            if not isinstance(site, dict):
                continue
            alerts = site.get("alerts")
            if not isinstance(alerts, list):
                continue
            for alert in alerts:
                if not isinstance(alert, dict) or not _text(alert.get("alert")):
                    continue
                instances = alert.get("instances")
                if not isinstance(instances, list):
                    continue
                for instance in instances:
                    if len(findings) >= cap:
                        logger.warning("ZAP instance cap %d reached", cap)
                        return findings
                    if isinstance(instance, dict) and _text(instance.get("uri")):
                        findings.append(self._finding(alert, instance))
        return findings

    def _plan(
        self, target: Target, work: Path, context: ScanContext | None
    ) -> dict[str, Any]:
        return build_plan(target, work, context, self.options)

    def _launcher(self) -> str | None:
        for name in LAUNCHERS:
            if self._check_tool_available(name):
                return name
        return None

    def _preflight(self, target: Target, context: ScanContext | None) -> None:
        parts = urlsplit(target.base_url)
        if parts.scheme not in ("http", "https"):
            raise ScopeViolation(f"scheme {parts.scheme!r} is not http or https")
        host = parts.hostname
        if not host or not target.scope.is_url_in_scope(target.base_url):
            raise ScopeViolation(f"{target.base_url} is outside the authorised scope")
        allow_private = self._allow_private(context)
        vetted = context.target_ip if context is not None and context.target_ip else ""
        if vetted:
            vet_addresses(host, [vetted], allow_private=allow_private)
            return
        try:
            addresses = _host_addresses(host, target.port)
        except OSError as exc:
            raise TransportError(f"cannot resolve {host}: {exc}") from exc
        vet_addresses(host, addresses, allow_private=allow_private)

    def _allow_private(self, context: ScanContext | None) -> bool:
        if self.options.get("allow_private") is True:
            return True
        http = getattr(context, "http", None)
        policy = getattr(http, "policy", None)
        return bool(getattr(policy, "allow_private", False))

    def _finding(self, alert: dict[str, Any], instance: dict[str, Any]) -> Finding:
        plugin = _text(alert.get("pluginid"))
        ref = _text(alert.get("alertRef"))
        tags = list(dict.fromkeys(tag for tag in (plugin, ref) if tag))
        reference = self._redact(_text(alert.get("reference")))
        return Finding(
            title=_text(alert.get("alert") or alert.get("name")),
            description=self._redact(_text(alert.get("desc"))),
            severity=_severities().get(_text(alert.get("riskcode")), Severity.INFO),
            confidence=_confidences().get(
                _text(alert.get("confidence")), Confidence.TENTATIVE
            ),
            url=_text(instance.get("uri")),
            parameter=self._redact(_text(instance.get("param"))),
            method=_text(instance.get("method")) or "GET",
            evidence=self._redact(_text(instance.get("evidence"))),
            remediation=self._redact(_text(alert.get("solution"))),
            references=[reference] if reference else [],
            scanner=self.name,
            tags=tags,
            cwe_id=_cwe(alert.get("cweid")),
            raw_data=self._redact_data(
                {
                    "pluginid": plugin,
                    "alertRef": ref,
                    "riskcode": _text(alert.get("riskcode")),
                    "confidence": _text(alert.get("confidence")),
                    "cweid": _text(alert.get("cweid")),
                    "wascid": _text(alert.get("wascid")),
                }
            ),
        )
