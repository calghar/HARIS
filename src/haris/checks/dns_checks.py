import ipaddress
import logging
from typing import Any, Protocol

from ..core.scanner import BaseScanner
from ..models import Finding, ScanContext, ScannerResult, Severity, Target
from .dns_wire import CAA, DNS_PORT, TXT, DnsError, UdpResolver, system_nameservers
from .findings import make_finding

logger = logging.getLogger(__name__)

MIN_LABELS = 2


class Resolver(Protocol):
    def lookup(self, name: str, rrtype: int) -> list[str]: ...


def parent_domains(host: str) -> list[str]:
    """*host* and each parent that still has at least two labels."""
    labels = host.lower().rstrip(".").split(".")
    return [".".join(labels[i:]) for i in range(len(labels) - MIN_LABELS + 1)]


def is_dns_name(host: str) -> bool:
    if "." not in host:
        return False
    try:
        ipaddress.ip_address(host)
    except ValueError:
        return True
    return False


class DnsRecordScanner(BaseScanner):
    """CAA, SPF and DMARC records of the target's domain (read-only DNS queries)."""

    name = "dns_checks"
    version = "1.0.0"
    description = "DNS hygiene: CAA, SPF and DMARC records"

    def __init__(self, options: dict[str, Any] | None = None) -> None:
        super().__init__(options)
        self.options.setdefault("nameservers", [])
        self.options.setdefault("dns_port", DNS_PORT)
        self.options.setdefault("dns_timeout", 3.0)

    def _resolver(self) -> Resolver:
        servers = self.options["nameservers"] or system_nameservers()
        return UdpResolver(
            servers, port=self.options["dns_port"], timeout=self.options["dns_timeout"]
        )

    def scan(self, target: Target, context: ScanContext | None = None) -> ScannerResult:
        result = ScannerResult(scanner_name=self.name)
        host = target.hostname
        if not is_dns_name(host):
            logger.debug("DNS checks skipped: %s is not a DNS name", host)
            return result
        resolver = self._resolver()
        domains = parent_domains(host)
        for kind, finder in (
            ("caa", self._caa),
            ("spf", self._spf),
            ("dmarc", self._dmarc),
        ):
            try:
                result.findings.extend(finder(resolver, host, domains))
            except DnsError as exc:
                result.errors.append(f"DNS {kind} lookup failed: {exc}")
        return result

    def parse_results(self, raw_output: str) -> list[Finding]:
        return []

    def _caa(self, resolver: Resolver, host: str, domains: list[str]) -> list[Finding]:
        for domain in domains:  # RFC 8659: the closest CAA set applies
            if resolver.lookup(domain, CAA):
                return []
        return [
            self._missing(
                host,
                kind="missing_caa",
                vuln_class="dns_missing_caa",
                title="No CAA record",
                description=(
                    f"No CAA record exists for {host} or its parent domains, so "
                    f"any certificate authority may issue certificates for it."
                ),
                remediation='Publish a CAA record, e.g. 0 issue "letsencrypt.org".',
            )
        ]

    def _spf(self, resolver: Resolver, host: str, domains: list[str]) -> list[Finding]:
        for domain in domains:
            if any(
                t.lower().startswith("v=spf1") for t in resolver.lookup(domain, TXT)
            ):
                return []
        return [
            self._missing(
                host,
                kind="missing_spf",
                vuln_class="dns_missing_spf",
                title="No SPF record",
                description=(
                    f"No TXT record starting with v=spf1 exists for {host} or its "
                    f"parent domains, so receivers cannot tell which servers may "
                    f"send its mail."
                ),
                remediation=(
                    'Publish an SPF record, or "v=spf1 -all" if no mail is sent.'
                ),
            )
        ]

    def _dmarc(
        self, resolver: Resolver, host: str, domains: list[str]
    ) -> list[Finding]:
        for domain in domains:
            records = resolver.lookup(f"_dmarc.{domain}", TXT)
            if any(t.lower().startswith("v=dmarc1") for t in records):
                return []
        return [
            self._missing(
                host,
                kind="missing_dmarc",
                vuln_class="dns_missing_dmarc",
                title="No DMARC record",
                description=(
                    f"No _dmarc TXT record with v=DMARC1 exists for {host} or its "
                    f"parent domains, so spoofed mail is not rejected."
                ),
                remediation=(
                    'Publish "_dmarc" TXT "v=DMARC1; p=quarantine; rua=mailto:..." '
                    "and tighten the policy once reports are clean."
                ),
            )
        ]

    def _missing(
        self,
        host: str,
        *,
        kind: str,
        vuln_class: str,
        title: str,
        description: str,
        remediation: str,
    ) -> Finding:
        return make_finding(
            self.name,
            kind,
            vuln_class,
            title=title,
            description=description,
            severity=Severity.LOW,
            url=f"https://{host}",
            evidence=f"DNS lookup for {host}: no matching record",
            remediation=remediation,
            tags=["security_misconfiguration"],
        )
