import logging
import socket
import ssl
from datetime import UTC, datetime
from typing import Any

from ..core.decorators import register_check
from ..core.scanner import BaseScanner
from ..models import Confidence, Finding, ScannerResult, Severity, Target

logger = logging.getLogger(__name__)


@register_check
class TLSCheckScanner(BaseScanner):
    """Basic TLS configuration checks using Python's ssl module.

    Checks certificate expiry, hostname match, and protocol support.
    For more thorough TLS analysis, use the SSLyze scanner.
    """

    name = "tls_checks"
    version = "1.0.0"
    description = "Basic TLS/certificate checks (no external tools)"

    def __init__(self, options: dict[str, Any] | None = None) -> None:
        super().__init__(options)
        self.options.setdefault("timeout", 15)
        self.options.setdefault("cert_expiry_warn_days", 30)

    def scan(self, target: Target, context: Any = None) -> ScannerResult:  # noqa: ARG002
        result = ScannerResult(scanner_name=self.name)

        if target.scheme != "https":
            result.findings.append(
                Finding(
                    title="Target uses HTTP instead of HTTPS",
                    description=(
                        f"{target.base_url} does not use TLS. All traffic "
                        f"is transmitted in cleartext."
                    ),
                    severity=Severity.HIGH,
                    confidence=Confidence.CONFIRMED,
                    url=target.base_url,
                    remediation="Enable HTTPS with a valid TLS certificate.",
                    scanner=self.name,
                    tags=["cleartext_transmission"],
                )
            )
            return result

        try:
            cert_info = self._get_cert_info(target.hostname, target.port)
        except Exception as exc:
            result.errors.append(f"TLS connection failed: {exc}")
            return result

        result.raw_output = str(cert_info)
        result.findings = self._analyse_cert(cert_info, target)
        return result

    def parse_results(self, raw_output: str) -> list[Finding]:
        return []

    def _get_cert_info(self, hostname: str, port: int) -> dict[str, Any]:
        """Connect to the host and retrieve certificate details."""
        context = ssl.create_default_context()
        with (
            socket.create_connection(
                (hostname, port), timeout=self.options["timeout"]
            ) as sock,
            context.wrap_socket(sock, server_hostname=hostname) as ssock,
        ):
            cert = ssock.getpeercert()
            protocol = ssock.version()
            cipher = ssock.cipher()
            return {
                "cert": cert,
                "protocol": protocol,
                "cipher": cipher,
            }

    def _analyse_cert(self, cert_info: dict[str, Any], target: Target) -> list[Finding]:
        findings: list[Finding] = []
        cert = cert_info.get("cert", {})
        protocol = cert_info.get("protocol", "")
        cipher = cert_info.get("cipher", ())

        # Check certificate expiry
        not_after_str = cert.get("notAfter", "")
        if not_after_str:
            try:
                not_after = datetime.strptime(
                    not_after_str, "%b %d %H:%M:%S %Y %Z"
                ).replace(tzinfo=UTC)
                now = datetime.now(UTC)
                days_left = (not_after - now).days

                if days_left < 0:
                    findings.append(
                        Finding(
                            title="TLS certificate has expired",
                            description=(
                                f"The certificate expired {abs(days_left)} days ago "
                                f"({not_after_str})."
                            ),
                            severity=Severity.CRITICAL,
                            confidence=Confidence.CONFIRMED,
                            url=target.base_url,
                            remediation="Renew the TLS certificate immediately.",
                            scanner=self.name,
                            tags=["weak_tls"],
                        )
                    )
                elif days_left < self.options["cert_expiry_warn_days"]:
                    findings.append(
                        Finding(
                            title="TLS certificate expiring soon",
                            description=(
                                f"The certificate expires in {days_left} days "
                                f"({not_after_str})."
                            ),
                            severity=Severity.MEDIUM,
                            confidence=Confidence.CONFIRMED,
                            url=target.base_url,
                            remediation="Renew the TLS certificate before expiry.",
                            scanner=self.name,
                            tags=["weak_tls"],
                        )
                    )
            except ValueError:
                logger.warning("Could not parse certificate date: %s", not_after_str)

        # Check negotiated protocol version
        weak_protocols = {"SSLv2", "SSLv3", "TLSv1", "TLSv1.1"}
        if protocol in weak_protocols:
            findings.append(
                Finding(
                    title=f"Weak TLS protocol negotiated: {protocol}",
                    description=(
                        f"The connection used {protocol}, which is deprecated."
                    ),
                    severity=Severity.HIGH,
                    confidence=Confidence.CONFIRMED,
                    url=target.base_url,
                    remediation="Configure the server to support only TLS 1.2+.",
                    scanner=self.name,
                    tags=["weak_tls"],
                )
            )

        # Check cipher strength (basic heuristic)
        if cipher and len(cipher) >= 3:
            cipher_name = cipher[0]
            key_bits = cipher[2]
            if key_bits and key_bits < 128:
                findings.append(
                    Finding(
                        title=f"Weak cipher suite: {cipher_name} ({key_bits}-bit)",
                        description=(
                            f"The negotiated cipher has a key length of only "
                            f"{key_bits} bits."
                        ),
                        severity=Severity.HIGH,
                        confidence=Confidence.CONFIRMED,
                        url=target.base_url,
                        evidence=f"Cipher: {cipher_name}, bits: {key_bits}",
                        remediation="Disable weak cipher suites (< 128-bit).",
                        scanner=self.name,
                        tags=["weak_cipher"],
                    )
                )

        return findings
