import math
import ssl
import time
from typing import Any

from ..core.decorators import register_check
from ..core.scanner import BaseScanner
from ..models import Finding, ScanContext, ScannerResult, Severity, Target
from ..net import NetworkError
from .findings import make_finding
from .requesting import scan_client
from .tls_probe import (
    HOSTNAME_MISMATCH_CODES,
    LEGACY_PROTOCOLS,
    TIME_CODES,
    TlsHandshake,
    cert_validity,
    fetch_certificate,
    supports_legacy_protocol,
    verification_failure,
)

SECONDS_PER_DAY = 86_400
MIN_CIPHER_BITS = 128


@register_check
class TLSCheckScanner(BaseScanner):
    """Certificate expiry, hostname and trust, deprecated protocols and weak ciphers.

    For more thorough TLS analysis, use the SSLyze scanner.
    """

    name = "tls_checks"
    version = "1.1.0"
    description = "Basic TLS/certificate checks (no external tools)"

    def __init__(self, options: dict[str, Any] | None = None) -> None:
        super().__init__(options)
        self.options.setdefault("timeout", 15)
        self.options.setdefault("cert_expiry_warn_days", 30)

    def scan(self, target: Target, context: ScanContext | None = None) -> ScannerResult:
        result = ScannerResult(scanner_name=self.name)
        if target.scheme != "https":
            result.findings.append(
                make_finding(
                    self.name,
                    "no_https",
                    "no_https",
                    title="Target uses HTTP instead of HTTPS",
                    description=(
                        f"{target.base_url} does not use TLS. All traffic "
                        f"is transmitted in cleartext."
                    ),
                    severity=Severity.HIGH,
                    url=target.base_url,
                    remediation="Enable HTTPS with a valid TLS certificate.",
                    tags=["cleartext_transmission"],
                )
            )
            return result

        with scan_client(target, context) as client:
            try:
                ip = client.preflight(target.base_url)
            except NetworkError as exc:
                result.errors.append(f"{type(exc).__name__}: {exc}")
                return result

        host, port, timeout = target.hostname, target.port, self.options["timeout"]
        legacy = [
            name
            for name, member in LEGACY_PROTOCOLS
            if supports_legacy_protocol(ip, port, host, member, timeout)
        ]
        result.findings.extend(self._protocol_finding(target, p) for p in legacy)
        try:
            handshake = fetch_certificate(ip, port, host, timeout)
        except (OSError, ssl.SSLError) as exc:
            if not legacy:
                result.errors.append(f"TLS connection failed: {exc}")
            return result

        result.raw_output = f"{handshake.protocol} {handshake.cipher}"
        result.findings.extend(self._analyse_cert(handshake, target, ip))
        result.findings.extend(self._check_cipher(handshake, target))
        return result

    def parse_results(self, raw_output: str) -> list[Finding]:
        return []

    def _protocol_finding(self, target: Target, protocol: str) -> Finding:
        return make_finding(
            self.name,
            "weak_protocol",
            "tls_weak_protocol",
            title=f"Weak TLS protocol supported: {protocol}",
            description=f"The server completed a {protocol} handshake (deprecated).",
            severity=Severity.HIGH,
            url=target.base_url,
            parameter=protocol,
            remediation="Configure the server to support only TLS 1.2+.",
            tags=["weak_tls"],
        )

    def _cert_finding(
        self,
        target: Target,
        kind: str,
        vuln_class: str,
        title: str,
        description: str,
        severity: Severity,
        remediation: str,
    ) -> Finding:
        return make_finding(
            self.name,
            kind,
            vuln_class,
            title=title,
            description=description,
            severity=severity,
            url=target.base_url,
            remediation=remediation,
            tags=["weak_tls"],
        )

    def _analyse_cert(
        self, handshake: TlsHandshake, target: Target, ip: str
    ) -> list[Finding]:
        findings: list[Finding] = []
        host, port, timeout = target.hostname, target.port, self.options["timeout"]
        validity = cert_validity(handshake.der)
        if validity:
            not_after = validity["notAfter"]
            expires_in = ssl.cert_time_to_seconds(not_after) - time.time()
            days_left = math.trunc(expires_in / SECONDS_PER_DAY)
            if expires_in < 0:
                findings.append(
                    self._cert_finding(
                        target,
                        "cert_expired",
                        "tls_cert_expired",
                        "TLS certificate has expired",
                        f"The certificate expired {abs(days_left)} days ago "
                        f"({not_after}).",
                        Severity.CRITICAL,
                        "Renew the TLS certificate immediately.",
                    )
                )
            elif days_left < self.options["cert_expiry_warn_days"]:
                findings.append(
                    self._cert_finding(
                        target,
                        "cert_expiring",
                        "tls_cert_expired",
                        "TLS certificate expiring soon",
                        f"The certificate expires in {days_left} days ({not_after}).",
                        Severity.MEDIUM,
                        "Renew the TLS certificate before expiry.",
                    )
                )

        mismatch = verification_failure(
            ip, port, host, handshake.der, timeout, trust_peer=True
        )
        if mismatch and mismatch.verify_code in HOSTNAME_MISMATCH_CODES:
            findings.append(
                self._cert_finding(
                    target,
                    "cert_hostname",
                    "tls_cert_hostname",
                    "TLS certificate does not match the hostname",
                    f"{mismatch.verify_message} (host: {host}).",
                    Severity.HIGH,
                    f"Issue a certificate that names {host} in its alternative names.",
                )
            )

        untrusted = verification_failure(
            ip, port, host, handshake.der, timeout, trust_peer=False
        )
        if untrusted and untrusted.verify_code not in (
            TIME_CODES | HOSTNAME_MISMATCH_CODES
        ):
            findings.append(
                self._cert_finding(
                    target,
                    "cert_untrusted",
                    "tls_cert_untrusted",
                    "TLS certificate is not trusted",
                    f"Chain validation failed: {untrusted.verify_message}.",
                    Severity.HIGH,
                    "Serve a certificate issued by a trusted CA with its full chain.",
                )
            )
        return findings

    def _check_cipher(self, handshake: TlsHandshake, target: Target) -> list[Finding]:
        if handshake.cipher is None or not 0 < handshake.cipher[2] < MIN_CIPHER_BITS:
            return []
        name, _, bits = handshake.cipher
        return [
            make_finding(
                self.name,
                "weak_cipher",
                "tls_weak_cipher",
                title=f"Weak cipher suite: {name} ({bits}-bit)",
                description=f"The negotiated cipher uses a {bits}-bit key.",
                severity=Severity.HIGH,
                url=target.base_url,
                parameter=name,
                evidence=f"Cipher: {name}, bits: {bits}",
                remediation="Disable weak cipher suites (< 128-bit).",
                tags=["weak_cipher"],
            )
        ]
