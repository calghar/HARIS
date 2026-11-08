import re

from ..core.decorators import register_check
from ..models import Finding, Severity, Target
from ..net import ScopedClient
from .findings import make_finding
from .probe_scanner import ProbeScanner
from .requesting import try_request

DIRECTORIES = (
    "/",
    "/uploads/",
    "/upload/",
    "/images/",
    "/img/",
    "/static/",
    "/assets/",
    "/files/",
    "/backup/",
    "/backups/",
    "/logs/",
    "/tmp/",  # nosec B108 - URL path to probe, not a local temp dir
    "/data/",
)
# Apache/nginx "Index of /", Python "Directory listing for /", IIS parent link.
LISTING_MARKER = re.compile(
    r"<title>\s*(?:Index of /|Directory listing for /)|\[To Parent Directory\]",
    re.IGNORECASE,
)
SPAN_CHARS = 60


@register_check
class DirectoryListingScanner(ProbeScanner):
    """Directories whose server-generated index page is publicly readable."""

    name = "listing_checks"
    version = "1.0.0"
    description = "Directory listing enabled"

    def probe(self, client: ScopedClient, target: Target) -> list[Finding]:
        findings: list[Finding] = []
        for directory in DIRECTORIES:
            url = target.base_url + directory
            resp = try_request(client, "GET", url)
            if resp is None or not 200 <= resp.status_code < 300:
                continue
            match = LISTING_MARKER.search(resp.text)
            if match is None or resp.redirect_chain:
                continue
            findings.append(
                make_finding(
                    self.name,
                    "directory_listing",
                    "directory_listing",
                    title=f"Directory listing enabled: {directory}",
                    description=(
                        f"{url} returns an auto-generated index of its files, so "
                        f"anyone can browse and download them."
                    ),
                    severity=Severity.MEDIUM,
                    url=url,
                    evidence=(
                        f"HTTP {resp.status_code}; "
                        f"matched {match.group(0)[:SPAN_CHARS]!r}"
                    ),
                    request_example=f"curl -s {url}",
                    remediation=(
                        "Disable directory indexing (Options -Indexes in Apache, "
                        "autoindex off in nginx)."
                    ),
                    tags=["security_misconfiguration"],
                )
            )
        return findings
