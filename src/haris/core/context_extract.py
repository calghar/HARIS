import logging
from collections.abc import Callable
from typing import Any

from ..data.scanner_config import get_nikto_tech_keywords
from ..models import ScannerResult
from ..models.scan_context import ScanContext

logger = logging.getLogger(__name__)

# Load Nikto tech keywords from config
_NIKTO_TECH_KEYWORDS = get_nikto_tech_keywords()

# nmap-services names of TLS web ports (443, 8443); "ssl/<name>" is matched in code.
NMAP_TLS_SERVICES = frozenset({"https", "https-alt", "ssl"})
NMAP_TLS_TUNNEL = "ssl"


def _extract_nikto_tech(msg: str, context: ScanContext) -> None:
    """Extract technology hints from a Nikto finding message."""
    msg_lower = msg.lower()
    for keyword, tech_name in _NIKTO_TECH_KEYWORDS:
        if keyword in msg_lower:
            context.add_technologies([tech_name])


def _is_tls_service(raw: dict[str, Any]) -> bool:
    """True when Nmap saw TLS on the port (``tunnel="ssl"`` or a TLS service name)."""
    service = str(raw.get("service", "")).lower()
    return (
        raw.get("tunnel") == NMAP_TLS_TUNNEL
        or service in NMAP_TLS_SERVICES
        or service.startswith("ssl/")
    )


def _extract_nmap(result: ScannerResult, context: ScanContext) -> None:
    """Extract ports, services and product info from Nmap findings."""
    for finding in result.findings:
        raw = finding.raw_data or {}
        port = raw.get("port", "")
        product = raw.get("product", "")
        service = raw.get("service", "")
        version = raw.get("version", "")
        if port:
            context.open_ports.append(str(port))
            if _is_tls_service(raw):
                context.tls_ports.append(str(port))
        techs = [t for t in [product, service] if t]
        if techs:
            context.add_technologies(techs)
        if product and version:
            context.add_technologies([f"{product}/{version}"])


def _extract_nikto_context(result: ScannerResult, context: ScanContext) -> None:
    """Extract technology hints from Nikto finding descriptions."""
    for finding in result.findings:
        msg = (finding.description or "").lower()
        _extract_nikto_tech(msg, context)


def _extract_header_checks(result: ScannerResult, context: ScanContext) -> None:
    """Extract server header technologies from header/misc/info checks."""
    for finding in result.findings:
        raw = finding.raw_data or {}
        for hdr_name in ("server", "x-powered-by", "x-aspnet-version"):
            val = raw.get(hdr_name, "")
            if val:
                context.server_headers[hdr_name] = val
                context.add_technologies([val])


# Dispatch dict mapping scanner name → context extractor function.
# Scanners not in this dict rely only on the generic URL collection
# performed in _extract_context before dispatching.
_CONTEXT_EXTRACTORS: dict[str, Callable[[ScannerResult, ScanContext], None]] = {
    "nmap": _extract_nmap,
    "nikto": _extract_nikto_context,
    "header_checks": _extract_header_checks,
    "misc_checks": _extract_header_checks,
    "info_disclosure": _extract_header_checks,
}


def extract_context(
    scanner_name: str,
    result: ScannerResult,
    context: ScanContext,
) -> None:
    """Add technologies, URLs and ports from *result* to *context*."""
    for finding in result.findings:
        if finding.url and finding.url.startswith("http"):
            context.add_urls([finding.url])

    extractor = _CONTEXT_EXTRACTORS.get(scanner_name)
    if extractor is not None:
        extractor(result, context)

    logger.debug(
        "Context after %s: %d techs, %d urls, %d ports",
        scanner_name,
        len(context.detected_technologies),
        len(context.discovered_urls),
        len(context.open_ports),
    )
