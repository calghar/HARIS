import json
import logging
import tempfile
from pathlib import Path
from typing import Any

from ..core.decorators import register_scanner
from ..core.scanner import BaseScanner
from ..data.scanner_config import (
    get_sslyze_deprecated_protocols,
    get_sslyze_vulnerability_checks,
)
from ..models import Confidence, Finding, ScannerResult, Severity, Target

logger = logging.getLogger(__name__)


@register_scanner
class SSLyzeScanner(BaseScanner):
    """Adapter for SSLyze TLS/SSL configuration scanner."""

    name = "sslyze"
    version = "6.x"
    description = "TLS/SSL configuration and certificate analyser"

    def __init__(self, options: dict[str, Any] | None = None) -> None:
        super().__init__(options)
        self.options.setdefault("timeout", 120)

    def scan(self, target: Target, context: Any = None) -> ScannerResult:  # noqa: ARG002
        if not self._check_tool_available("sslyze"):
            return ScannerResult(
                scanner_name=self.name,
                errors=["sslyze is not installed or not on PATH"],
            )

        with tempfile.TemporaryDirectory() as tmpdir:
            output_file = Path(tmpdir) / "sslyze_results.json"

            hostname_port = f"{target.hostname}:{target.port}"
            cmd = [
                "sslyze",
                hostname_port,
                "--json_out",
                str(output_file),
                "--quiet",
            ]

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
                    f"sslyze exited with code {returncode}: {stderr[:500]}"
                )

            if raw:
                result.findings = self.parse_results(raw)

            return result

    def parse_results(self, raw_output: str) -> list[Finding]:
        """Parse SSLyze JSON output into Finding objects."""
        findings: list[Finding] = []

        try:
            data = json.loads(raw_output)
        except json.JSONDecodeError as exc:
            logger.error("Failed to parse SSLyze JSON: %s", exc)
            return findings

        for server_result in data.get("server_scan_results", []):
            scan_result = server_result.get("scan_result", {})
            hostname = server_result.get("server_location", {}).get("hostname", "")

            findings.extend(self._check_protocols(scan_result, hostname))
            findings.extend(self._check_certificate(scan_result, hostname))
            findings.extend(self._check_vulnerabilities(scan_result, hostname))

        return findings

    def _check_protocols(self, scan_result: dict, hostname: str) -> list[Finding]:
        """Flag deprecated TLS/SSL protocols."""
        findings: list[Finding] = []
        deprecated_protos = get_sslyze_deprecated_protocols()

        for key, proto_info in deprecated_protos.items():
            proto_name = proto_info["proto_name"]
            severity = Severity[proto_info["severity"]]
            proto_result = scan_result.get(key, {})
            if not proto_result:
                continue
            result_obj = proto_result.get("result", {})
            accepted = result_obj.get("accepted_cipher_suites", [])
            if accepted:
                cipher_names = [
                    c.get("cipher_suite", {}).get("name", "unknown")
                    for c in accepted[:5]
                ]
                findings.append(
                    Finding(
                        title=f"Deprecated protocol {proto_name} supported",
                        description=(
                            f"The server accepts connections via {proto_name}, "
                            f"which is deprecated and has known vulnerabilities."
                        ),
                        severity=severity,
                        confidence=Confidence.CONFIRMED,
                        url=f"https://{hostname}/",
                        evidence=f"Accepted ciphers: {', '.join(cipher_names)}",
                        remediation=(
                            f"Disable {proto_name} on the server. Only TLS 1.2 "
                            f"and TLS 1.3 should be enabled."
                        ),
                        references=[
                            "https://www.ssllabs.com/ssltest/",
                        ],
                        scanner=self.name,
                        tags=["weak_tls"],
                    )
                )

        return findings

    def _check_certificate(self, scan_result: dict, hostname: str) -> list[Finding]:
        """Check certificate validity and chain issues."""
        findings: list[Finding] = []
        cert_info = scan_result.get("certificate_info", {})
        if not cert_info:
            return findings

        result_obj = cert_info.get("result", {})
        deployments = result_obj.get("certificate_deployments", [])

        for deployment in deployments:
            # Check trust
            path_results = deployment.get("path_validation_results", [])
            for pvr in path_results:
                if pvr.get("was_validation_successful") is False:
                    trust_store = pvr.get("trust_store", {}).get("name", "")
                    findings.append(
                        Finding(
                            title="Certificate not trusted",
                            description=(
                                f"Certificate chain validation failed for "
                                f"trust store: {trust_store}."
                            ),
                            severity=Severity.HIGH,
                            confidence=Confidence.CONFIRMED,
                            url=f"https://{hostname}/",
                            remediation=(
                                "Ensure a valid certificate chain from a trusted CA."
                            ),
                            scanner=self.name,
                            tags=["weak_tls"],
                        )
                    )
                    break  # one finding per deployment is enough

            # Check hostname match
            if not deployment.get("leaf_certificate_subject_matches_hostname", True):
                findings.append(
                    Finding(
                        title="Certificate hostname mismatch",
                        description=(
                            "The certificate's subject does not match the "
                            f"server hostname ({hostname})."
                        ),
                        severity=Severity.HIGH,
                        confidence=Confidence.CONFIRMED,
                        url=f"https://{hostname}/",
                        remediation=(
                            "Use a certificate that covers the target hostname."
                        ),
                        scanner=self.name,
                        tags=["weak_tls"],
                    )
                )

        return findings

    def _check_vulnerabilities(self, scan_result: dict, hostname: str) -> list[Finding]:
        """Check for known TLS vulnerabilities (Heartbleed, ROBOT, etc.)."""
        findings: list[Finding] = []
        vuln_checks = get_sslyze_vulnerability_checks()

        for check_name, check_info in vuln_checks.items():
            check_data = scan_result.get(check_info["key"], {})
            if not check_data:
                continue

            result_obj = check_data.get("result", {})

            vulnerable_values = check_info.get("vulnerable_values")
            if vulnerable_values is not None:
                assert isinstance(vulnerable_values, list)
                is_vuln = (
                    result_obj.get(str(check_info["result_field"]), "")
                    in vulnerable_values
                )
            else:
                is_vuln = result_obj.get(str(check_info["result_field"]), False)

            if is_vuln:
                title = str(check_info["title"])
                severity = Severity[check_info["severity"]]
                findings.append(
                    Finding(
                        title=title,
                        description=(f"Server is vulnerable to {check_name}."),
                        severity=severity,
                        confidence=Confidence.CONFIRMED,
                        url=f"https://{hostname}/",
                        remediation="Update the TLS library and server software.",
                        scanner=self.name,
                        tags=["weak_tls"],
                    )
                )

        return findings
