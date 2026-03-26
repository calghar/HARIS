from pydantic import BaseModel, Field


class ScanContext(BaseModel):
    """Cross-scanner intelligence accumulated during a scan session.

    Built incrementally by :class:`~src.core.engine.ScanEngine` as each
    scanner completes.  Downstream scanners can read this context to
    make smarter template/module selections.
    """

    detected_technologies: list[str] = Field(
        default_factory=list,
        description=(
            "Technologies detected by earlier scanners"
            " (e.g. 'nginx', 'wordpress', 'php')."
        ),
    )
    discovered_urls: list[str] = Field(
        default_factory=list,
        description="URLs discovered by crawling scanners (e.g. Wapiti).",
    )
    open_ports: list[str] = Field(
        default_factory=list,
        description="Open ports from Nmap results (e.g. '80', '443', '8080').",
    )
    server_headers: dict[str, str] = Field(
        default_factory=dict,
        description="Server response headers captured by earlier scanners.",
    )

    def add_technologies(self, techs: list[str]) -> None:
        """Add technologies, de-duplicating by lowercase."""
        existing = {t.lower() for t in self.detected_technologies}
        for tech in techs:
            if tech.lower() not in existing:
                self.detected_technologies.append(tech.lower())
                existing.add(tech.lower())

    def add_urls(self, urls: list[str]) -> None:
        """Add URLs, de-duplicating."""
        existing = set(self.discovered_urls)
        for url in urls:
            if url not in existing:
                self.discovered_urls.append(url)
                existing.add(url)
