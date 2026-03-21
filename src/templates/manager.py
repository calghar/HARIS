import json
import logging
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from ..models.templates import (
    TemplateConfig,
    TemplateMetadata,
    TemplateSource,
    UpdateResult,
)
from .adapters import get_adapter

logger = logging.getLogger(__name__)

_SCANNER_DIRS = ["nuclei", "nikto", "nmap", "wapiti"]


class TemplateManager:
    """Manages template sources for all scanners.

    Typical lifecycle::

        mgr = TemplateManager.from_config(config.template_config)
        mgr.init_directory()                 # first-time setup
        results = mgr.update_templates()     # fetch / refresh
        opts = mgr.get_scanner_options("nuclei")  # merge into scanner
    """

    def __init__(
        self,
        base_dir: str | Path = "./templates",
        sources: list[TemplateSource] | None = None,
    ) -> None:
        self.base_dir = Path(base_dir)
        self.sources: list[TemplateSource] = sources or []
        self._metadata_path = self.base_dir / "metadata.json"

    @classmethod
    def from_config(cls, config: TemplateConfig) -> "TemplateManager":
        """Factory: build from a :class:`TemplateConfig`."""
        return cls(
            base_dir=config.template_dir,
            sources=config.sources,
        )

    # ------------------------------------------------------------------
    # Directory management
    # ------------------------------------------------------------------

    def init_directory(self) -> None:
        """Create the template directory tree if it does not exist."""
        self.base_dir.mkdir(parents=True, exist_ok=True)
        for scanner in _SCANNER_DIRS:
            (self.base_dir / scanner / "custom").mkdir(
                parents=True, exist_ok=True,
            )
        logger.info("Template directory initialised at %s", self.base_dir)

    # ------------------------------------------------------------------
    # Source management
    # ------------------------------------------------------------------

    def add_source(self, source: TemplateSource) -> None:
        """Add a template source (idempotent by name)."""
        for i, existing in enumerate(self.sources):
            if existing.name == source.name:
                self.sources[i] = source
                return
        self.sources.append(source)

    def remove_source(self, source_name: str) -> bool:
        """Remove a source by name.  Returns True if found."""
        before = len(self.sources)
        self.sources = [s for s in self.sources if s.name != source_name]
        return len(self.sources) < before

    # ------------------------------------------------------------------
    # Update
    # ------------------------------------------------------------------

    def update_templates(
        self,
        scanner_name: str | None = None,
        force: bool = False,
    ) -> list[UpdateResult]:
        """Update templates for one or all scanners.

        Args:
            scanner_name: If given, only update this scanner's sources.
            force: Re-download even if already up to date.

        Returns:
            A list of :class:`UpdateResult`, one per source processed.
        """
        self.init_directory()
        metadata = self._load_metadata()
        results: list[UpdateResult] = []

        for source in self.sources:
            if not source.enabled:
                continue
            if scanner_name and source.scanner != scanner_name:
                continue

            adapter = get_adapter(source.scanner)
            if adapter is None:
                results.append(UpdateResult(
                    scanner=source.scanner,
                    source_name=source.name,
                    success=False,
                    error=f"No template adapter for scanner '{source.scanner}'",
                ))
                continue

            target_dir = self.base_dir / source.scanner / source.name
            logger.info(
                "Updating templates: %s (%s)", source.name, source.scanner,
            )

            result = adapter.update(source, target_dir, force=force)
            results.append(result)

            if result.success:
                metadata[source.name] = TemplateMetadata(
                    source_name=source.name,
                    scanner=source.scanner,
                    version=result.new_version,
                    last_updated=datetime.now(UTC).isoformat(),
                    template_count=result.templates_added,
                    local_path=result.local_path or str(target_dir),
                )

        self._save_metadata(metadata)
        return results

    # ------------------------------------------------------------------
    # Scanner option injection
    # ------------------------------------------------------------------

    def get_scanner_options(self, scanner_name: str) -> dict[str, Any]:
        """Return template-derived options to merge into a scanner's config.

        For example, for Nuclei this returns
        ``{"templates": ["/path/to/nuclei/official", ...]}``.
        """
        adapter = get_adapter(scanner_name)
        if adapter is None:
            return {}

        scanner_sources = [
            s for s in self.sources
            if s.scanner == scanner_name and s.enabled
        ]
        if not scanner_sources:
            return {}

        return adapter.get_scanner_options(self.base_dir, scanner_sources)

    # ------------------------------------------------------------------
    # Querying
    # ------------------------------------------------------------------

    def list_sources(self) -> list[TemplateMetadata]:
        """Return metadata for all tracked sources."""
        metadata = self._load_metadata()
        return list(metadata.values())

    def get_source_metadata(self, source_name: str) -> TemplateMetadata | None:
        """Look up metadata for a single source."""
        metadata = self._load_metadata()
        return metadata.get(source_name)

    # ------------------------------------------------------------------
    # Metadata persistence
    # ------------------------------------------------------------------

    def _load_metadata(self) -> dict[str, TemplateMetadata]:
        if not self._metadata_path.exists():
            return {}
        try:
            raw = json.loads(self._metadata_path.read_text())
            return {
                k: TemplateMetadata(**v) for k, v in raw.items()
            }
        except Exception as exc:
            logger.warning("Could not load template metadata: %s", exc)
            return {}

    def _save_metadata(self, metadata: dict[str, TemplateMetadata]) -> None:
        self._metadata_path.parent.mkdir(parents=True, exist_ok=True)
        data = {k: v.model_dump() for k, v in metadata.items()}
        self._metadata_path.write_text(
            json.dumps(data, indent=2, default=str) + "\n",
        )
