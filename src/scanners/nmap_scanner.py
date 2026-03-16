import logging
import xml.etree.ElementTree as ET
from typing import Any

from ..core.decorators import register_scanner
from ..core.scanner import BaseScanner
from ..models import Confidence, Finding, ScannerResult, Severity, Target

logger = logging.getLogger(__name__)


@register_scanner
class NmapScanner(BaseScanner):
    """Adapter for Nmap network scanner (recon / port scan).

    Requires ``nmap`` to be installed and on PATH.
    By default runs a service-version scan on common web ports.
    """

    name = "nmap"
    version = "7.x"
    description = "Network reconnaissance and port/service scanner"

    def __init__(self, options: dict[str, Any] | None = None) -> None:
        super().__init__(options)
        self.options.setdefault("ports", "80,443,8080,8443,8000,8888")
        self.options.setdefault("timeout", 300)
        # Only service version detection, no aggressive scripts
        self.options.setdefault("extra_args", ["-sV", "--open"])

    def scan(self, target: Target) -> ScannerResult:
        if not self._check_tool_available("nmap"):
            return ScannerResult(
                scanner_name=self.name,
                errors=["nmap is not installed or not on PATH"],
            )

        import tempfile
        from pathlib import Path

        with tempfile.TemporaryDirectory() as tmpdir:
            output_file = Path(tmpdir) / "nmap_results.xml"

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

            if returncode != 0 and not raw:
                result.errors.append(
                    f"nmap exited with code {returncode}: {stderr[:500]}"
                )

            if raw:
                result.findings = self.parse_results(raw)

            return result

    def parse_results(self, raw_output: str) -> list[Finding]:
        """Parse Nmap XML output into Finding objects."""
        findings: list[Finding] = []

        try:
            root = ET.fromstring(raw_output)
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
            hostname = (
                hostname_el.get("name", ip_addr)
                if hostname_el is not None
                else ip_addr
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

                if service_el is not None:
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
                    },
                )
                findings.append(finding)

                # Flag potentially dangerous services
                findings.extend(
                    self._flag_risky_service(
                        hostname, port_id,
                        service_name, service_product,
                    )
                )

                # Flag outdated server versions if detectable
                if service_version:
                    findings.extend(
                        self._flag_version_info(
                            hostname, port_id, service_product,
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
        risky = {
            "ftp": "FTP can transmit credentials in cleartext",
            "telnet": "Telnet transmits all data in cleartext",
            "mysql": "Database port exposed to the network",
            "postgresql": "Database port exposed to the network",
            "redis": "Redis often has no authentication by default",
            "mongodb": "MongoDB may lack authentication",
            "memcached": "Memcached should not be publicly accessible",
            "elasticsearch": "Elasticsearch may expose sensitive data",
        }

        findings: list[Finding] = []
        service_lower = service.lower()

        for svc, reason in risky.items():
            if svc in service_lower or svc in (product or "").lower():
                findings.append(Finding(
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
                ))
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
            findings.append(Finding(
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
            ))

        return findings

    def _build_command(self, target: Target, output_path: str) -> list[str]:
        cmd = [
            "nmap",
            "-oX", output_path,
            "-p", self.options["ports"],
        ]
        cmd.extend(self.options.get("extra_args", []))
        cmd.append(target.hostname)
        return cmd
