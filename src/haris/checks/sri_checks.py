from html.parser import HTMLParser
from urllib.parse import urljoin, urlsplit

from ..core.decorators import register_check
from ..models import Finding, Severity, Target
from ..net import ScopedClient
from .findings import make_finding
from .probe_scanner import ProbeScanner
from .requesting import fetch_page, is_html

MAX_REPORTED_RESOURCES = 25


class _ResourceParser(HTMLParser):
    """Collects ``<script src>`` and stylesheet ``<link href>`` with their SRI state."""

    def __init__(self) -> None:
        super().__init__()
        self.resources: list[tuple[str, str, bool]] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        values = {k.lower(): v or "" for k, v in attrs}
        if tag == "script" and values.get("src"):
            kind, url = "script", values["src"]
        elif tag == "link" and "stylesheet" in values.get("rel", "").lower().split():
            kind, url = "stylesheet", values.get("href", "")
        else:
            return
        if url:
            self.resources.append((kind, url, bool(values.get("integrity"))))


def _is_third_party(url: str, host: str) -> bool:
    other = urlsplit(url).hostname or ""
    return bool(other) and other != host and not other.endswith(f".{host}")


@register_check
class SriScanner(ProbeScanner):
    """Third-party scripts and stylesheets loaded without Subresource Integrity."""

    name = "sri_checks"
    version = "1.0.0"
    description = "Subresource Integrity on third-party resources"

    def probe(self, client: ScopedClient, target: Target) -> list[Finding]:
        page = fetch_page(client, target.base_url)
        if not 200 <= page.status_code < 300 or not is_html(page):
            return []
        parser = _ResourceParser()
        parser.feed(page.text)
        findings: list[Finding] = []
        reported: set[str] = set()
        for kind, raw_url, has_integrity in parser.resources:
            url = urljoin(page.url, raw_url)
            if (
                has_integrity
                or url in reported
                or not _is_third_party(url, target.hostname)
            ):
                continue
            reported.add(url)
            findings.append(
                make_finding(
                    self.name,
                    "missing_sri",
                    "missing_sri",
                    title=f"Third-party {kind} loaded without integrity check",
                    description=(
                        f"{target.base_url} loads the {kind} {url} from another "
                        f"origin with no integrity attribute, so a compromise of "
                        f"that origin runs attacker code on the page."
                    ),
                    severity=Severity.LOW,
                    url=target.base_url,
                    parameter=url,
                    evidence=f"{kind}: {url}",
                    remediation=(
                        'Add integrity="sha384-..." and crossorigin="anonymous", '
                        "or host the file on your own origin."
                    ),
                    tags=["security_misconfiguration"],
                )
            )
            if len(findings) >= MAX_REPORTED_RESOURCES:
                break
        return findings
