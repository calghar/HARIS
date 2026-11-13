import logging
import tempfile
import xml.etree.ElementTree as ET  # noqa: N817
from pathlib import Path
from typing import Any

from ..core.decorators import handle_scanner_errors
from ..data.scanner_config import (
    get_nmap_default_extra_args,
    get_nmap_default_ports,
    get_nmap_risky_services,
)
from ..models import Confidence, Finding, ScannerResult, Severity, Target
from .argv_policy import ExtraArgsError
from .base import ExternalToolScanner, compact_number, is_ip_literal

logger = logging.getLogger(__name__)

NSE_SUFFIX = ".nse"


class NmapScanner(ExternalToolScanner):
    """Adapter for Nmap network scanner (recon / port scan).

    Requires ``nmap`` to be installed and on PATH.
    By default runs a service-version scan on common web ports.
    ``nse_scripts`` lists local ``.nse`` files (from the template manager).
    """

    name = "nmap"
    binds_to = "target_ip"
    version = "7.x"
    description = "Network reconnaissance and port/service scanner"

    def __init__(self, options: dict[str, Any] | None = None) -> None:
        super().__init__(options)
        self.options.setdefault("ports", get_nmap_default_ports())
        self.options.setdefault("timeout", 300)
        self.options.setdefault("extra_args", get_nmap_default_extra_args())
        self.options.setdefault("nse_scripts", [])

    @handle_scanner_errors
    def scan(self, target: Target, context: Any = None) -> ScannerResult:
        if (refusal := self._unbound(target, context)) is not None:
            return refusal
        if not self._check_tool_available("nmap"):
            return ScannerResult(
                scanner_name=self.name,
                errors=["nmap is not installed or not on PATH"],
            )
        self._begin(target, context)

        with tempfile.TemporaryDirectory() as tmpdir:
            output_file = Path(tmpdir) / "nmap_results.xml"
            cmd = self._build_command(target, str(output_file))
            timeout = self.options["timeout"]
            run = self._run_to_file(cmd, output_file, timeout)

        result = ScannerResult(scanner_name=self.name, raw_output=run.raw)
        if run.timed_out:
            result.errors.append(self._timeout_error(timeout))
        elif run.returncode != 0 and not run.raw:
            result.errors.append(
                f"nmap exited with code {run.returncode}: {run.stderr[:500]}"
            )
        if run.raw:
            result.findings = self.parse_results(run.raw, alias=self._alias(target))
        return result

    def parse_results(self, raw_output: str, alias: str = "") -> list[Finding]:
        """Parse Nmap XML; *alias* names a host nmap scanned by address."""
        findings: list[Finding] = []

        try:
            root = ET.fromstring(raw_output)  # nosec B314 — nmap output is trusted local tool data
        except ET.ParseError as exc:
            logger.error("Failed to parse Nmap XML: %s", exc)
            return findings

        for host in root.findall(".//host"):
            address_el = host.find("address")
            ip_addr = (
                address_el.get("addr", "unknown")
                if address_el is not None
                else "unknown"
            )

            hostname_el = host.find(".//hostname")
            hostname = alias or (
                hostname_el.get("name", ip_addr) if hostname_el is not None else ip_addr
            )

            ports_el = host.find("ports")
            if ports_el is None:
                continue

            for port_el in ports_el.findall("port"):
                port_id = port_el.get("portid", "")
                protocol = port_el.get("protocol", "tcp")

                state_el = port_el.find("state")
                if state_el is None:
                    continue
                state = state_el.get("state", "")
                if state != "open":
                    continue

                service_el = port_el.find("service")
                service_name = ""
                service_product = ""
                service_version = ""
                service_tunnel = ""

                if service_el is not None:
                    service_tunnel = service_el.get("tunnel", "")
                    service_name = service_el.get("name", "")
                    service_product = service_el.get("product", "")
                    service_version = service_el.get("version", "")

                full_service = " ".join(
                    filter(None, [service_product, service_version])
                )

                # Informational finding for each open port
                finding = Finding(
                    title=f"Open port {port_id}/{protocol}: {service_name}",
                    description=(
                        f"Port {port_id}/{protocol} is open on {hostname} "
                        f"({ip_addr}), running "
                        f"{full_service or service_name or 'unknown service'}."
                    ),
                    severity=Severity.INFO,
                    confidence=Confidence.CONFIRMED,
                    url=f"{hostname}:{port_id}",
                    evidence=f"Service: {full_service or service_name}",
                    scanner=self.name,
                    tags=["security_misconfiguration"],
                    raw_data={
                        "port": port_id,
                        "protocol": protocol,
                        "service": service_name,
                        "product": service_product,
                        "version": service_version,
                        "tunnel": service_tunnel,
                    },
                )
                findings.append(finding)

                # Flag potentially dangerous services
                findings.extend(
                    self._flag_risky_service(
                        hostname,
                        port_id,
                        service_name,
                        service_product,
                    )
                )

                # Flag outdated server versions if detectable
                if service_version:
                    findings.extend(
                        self._flag_version_info(
                            hostname,
                            port_id,
                            service_product,
                            service_version,
                        )
                    )

        return findings

    def _flag_risky_service(
        self,
        hostname: str,
        port: str,
        service: str,
        product: str,
    ) -> list[Finding]:
        """Flag services that should not normally be exposed."""
        risky = get_nmap_risky_services()

        findings: list[Finding] = []
        service_lower = service.lower()

        for svc, reason in risky.items():
            if svc in service_lower or svc in (product or "").lower():
                findings.append(
                    Finding(
                        title=f"Exposed {svc} service on port {port}",
                        description=(
                            f"{svc.upper()} service detected on "
                            f"{hostname}:{port}. {reason}."
                        ),
                        severity=Severity.HIGH,
                        confidence=Confidence.CONFIRMED,
                        url=f"{hostname}:{port}",
                        remediation=(
                            f"Restrict access to {svc} via firewall rules "
                            f"or bind it to localhost."
                        ),
                        scanner=self.name,
                        tags=["security_misconfiguration"],
                    )
                )
                break

        return findings

    def _flag_version_info(
        self,
        hostname: str,
        port: str,
        product: str,
        version: str,
    ) -> list[Finding]:
        """Flag when server version information is disclosed."""
        findings: list[Finding] = []

        if product and version:
            findings.append(
                Finding(
                    title=f"Server version disclosed: {product} {version}",
                    description=(
                        f"The server on {hostname}:{port} discloses its "
                        f"software version ({product} {version}). This "
                        f"information aids attackers in identifying known "
                        f"vulnerabilities for that version."
                    ),
                    severity=Severity.LOW,
                    confidence=Confidence.CONFIRMED,
                    url=f"{hostname}:{port}",
                    evidence=f"{product} {version}",
                    remediation=(
                        "Suppress version information in server banners "
                        "and HTTP headers."
                    ),
                    scanner=self.name,
                    tags=["outdated_server"],
                )
            )

        return findings

    def _alias(self, target: Target) -> str:
        """Hostname to report when nmap scans the vetted address instead of it."""
        return "" if is_ip_literal(target.hostname) else target.hostname

    def _build_command(self, target: Target, output_path: str) -> list[str]:
        cmd = [
            "nmap",
            "-n",
            "-oX",
            output_path,
            "-p",
            self.options["ports"],
        ]
        cmd.extend(self._extra_args())
        scripts = self._nse_scripts()
        if scripts:
            cmd.extend(["--script", ",".join(scripts)])
        if self._rate_rps > 0:
            # After extra_args: nmap keeps the last --max-rate.
            cmd.extend(["--max-rate", compact_number(self._rate_rps)])
        cmd.extend(["--", (self._alias(target) and self._vetted_ip) or target.hostname])
        return cmd

    def _nse_scripts(self) -> list[str]:
        scripts = [str(s) for s in self.options.get("nse_scripts", [])]
        for script in scripts:
            if "," in script or not (
                script.endswith(NSE_SUFFIX) and Path(script).is_file()
            ):
                raise ExtraArgsError(f"nse_scripts entry {script!r} is not a .nse file")
        return scripts
