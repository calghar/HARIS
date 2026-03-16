import abc
import logging
import shutil
from pathlib import Path
from typing import Any

from ..models.templates import TemplateSource, UpdateResult
from .updater import TemplateUpdater

logger = logging.getLogger(__name__)


class BaseScannerTemplateAdapter(abc.ABC):
    """Base interface for scanner-specific template management."""

    scanner_name: str = ""
    """Must match the scanner's registered name."""

    file_patterns: list[str] = ["*"]
    """Glob patterns for counting template files."""

    @abc.abstractmethod
    def update(
        self,
        source: TemplateSource,
        target_dir: Path,
        force: bool = False,
    ) -> UpdateResult:
        """Fetch or refresh templates from *source* into *target_dir*."""

    def list_templates(self, template_dir: Path) -> list[str]:
        """Return relative paths of all template files in *template_dir*."""
        if not template_dir.is_dir():
            return []
        results: list[str] = []
        seen: set[Path] = set()
        for pattern in self.file_patterns:
            for p in template_dir.rglob(pattern):
                if p.is_file() and p not in seen:
                    seen.add(p)
                    results.append(str(p.relative_to(template_dir)))
        return sorted(results)

    @abc.abstractmethod
    def get_scanner_options(
        self,
        template_dir: Path,
        sources: list[TemplateSource],
    ) -> dict[str, Any]:
        """Return scanner option overrides derived from template paths."""


# ------------------------------------------------------------------
# Nuclei
# ------------------------------------------------------------------

class NucleiTemplateAdapter(BaseScannerTemplateAdapter):
    """Manages nuclei-templates: YAML template files."""

    scanner_name = "nuclei"
    file_patterns = ["*.yaml", "*.yml"]

    def update(
        self,
        source: TemplateSource,
        target_dir: Path,
        force: bool = False,
    ) -> UpdateResult:
        updater = TemplateUpdater()
        prev_version = updater.get_git_version(target_dir)

        if source.source_type == "git":
            if not force and (target_dir / ".git").is_dir():
                ok = updater.git_clone_or_pull(
                    source.url, target_dir, source.branch,
                )
            else:
                # Force: wipe and re-clone
                if force and target_dir.is_dir():
                    shutil.rmtree(target_dir)
                ok = updater.git_clone_or_pull(
                    source.url, target_dir, source.branch,
                )
        else:
            ok = False

        new_version = updater.get_git_version(target_dir) if ok else ""
        count = updater.count_files(target_dir, self.file_patterns)

        return UpdateResult(
            scanner=self.scanner_name,
            source_name=source.name,
            success=ok,
            previous_version=prev_version,
            new_version=new_version,
            templates_added=count,
            error="" if ok else "Update failed",
        )

    def get_scanner_options(
        self,
        template_dir: Path,
        sources: list[TemplateSource],
    ) -> dict[str, Any]:
        """Return ``{"templates": [path1, path2, ...]}``."""
        paths: list[str] = []
        for source in sources:
            if not source.enabled:
                continue
            if source.source_type == "local" and source.local_path:
                paths.append(source.local_path)
            else:
                src_dir = template_dir / self.scanner_name / source.name
                if src_dir.is_dir():
                    paths.append(str(src_dir))

        # Always include the custom directory if it exists
        custom = template_dir / self.scanner_name / "custom"
        if custom.is_dir() and any(custom.iterdir()):
            paths.append(str(custom))

        return {"templates": paths} if paths else {}


# ------------------------------------------------------------------
# Nikto
# ------------------------------------------------------------------

class NiktoTemplateAdapter(BaseScannerTemplateAdapter):
    """Manages nikto databases and plugins."""

    scanner_name = "nikto"
    file_patterns = ["db_*", "*.db", "*.plugin"]

    def update(
        self,
        source: TemplateSource,
        target_dir: Path,
        force: bool = False,
    ) -> UpdateResult:
        updater = TemplateUpdater()
        prev_version = updater.get_git_version(target_dir)

        if source.source_type == "git":
            if force and target_dir.is_dir():
                shutil.rmtree(target_dir)
            ok = updater.git_clone_or_pull(
                source.url, target_dir, source.branch,
            )
        else:
            ok = False

        new_version = updater.get_git_version(target_dir) if ok else ""
        count = updater.count_files(target_dir, self.file_patterns)

        return UpdateResult(
            scanner=self.scanner_name,
            source_name=source.name,
            success=ok,
            previous_version=prev_version,
            new_version=new_version,
            templates_added=count,
            error="" if ok else "Update failed",
        )

    def get_scanner_options(
        self,
        template_dir: Path,
        sources: list[TemplateSource],
    ) -> dict[str, Any]:
        """Nikto supports a custom user database via ``-dbcheck``."""
        # Look for user_scan_database.db or custom db files
        custom = template_dir / self.scanner_name / "custom"
        extra_args: list[str] = []
        if custom.is_dir():
            for db_file in sorted(custom.glob("*.db")):
                extra_args.extend(["-useproxy", str(db_file)])

        return {"extra_args": extra_args} if extra_args else {}


# ------------------------------------------------------------------
# Nmap
# ------------------------------------------------------------------

class NmapTemplateAdapter(BaseScannerTemplateAdapter):
    """Manages NSE (Nmap Scripting Engine) scripts."""

    scanner_name = "nmap"
    file_patterns = ["*.nse"]

    def update(
        self,
        source: TemplateSource,
        target_dir: Path,
        force: bool = False,
    ) -> UpdateResult:
        updater = TemplateUpdater()
        prev_version = updater.get_git_version(target_dir)

        if source.source_type == "git":
            if force and target_dir.is_dir():
                shutil.rmtree(target_dir)
            ok = updater.git_clone_or_pull(
                source.url, target_dir, source.branch,
            )
        elif source.source_type == "url":
            ok = updater.download_file(source.url, target_dir / "custom.nse")
        else:
            ok = False

        new_version = updater.get_git_version(target_dir) if ok else ""
        count = updater.count_files(target_dir, self.file_patterns)

        return UpdateResult(
            scanner=self.scanner_name,
            source_name=source.name,
            success=ok,
            previous_version=prev_version,
            new_version=new_version,
            templates_added=count,
            error="" if ok else "Update failed",
        )

    def get_scanner_options(
        self,
        template_dir: Path,
        sources: list[TemplateSource],
    ) -> dict[str, Any]:
        """Return ``--script`` paths for custom NSE scripts."""
        scripts: list[str] = []
        custom = template_dir / self.scanner_name / "custom"
        if custom.is_dir():
            for nse in sorted(custom.glob("*.nse")):
                scripts.append(str(nse))

        if not scripts:
            return {}
        return {"extra_args": [
            "--script", ",".join(scripts),
        ]}


# ------------------------------------------------------------------
# Wapiti
# ------------------------------------------------------------------

class WapitiTemplateAdapter(BaseScannerTemplateAdapter):
    """Manages wapiti modules and custom payloads."""

    scanner_name = "wapiti"
    file_patterns = ["*.py", "*.txt", "*.json"]

    def update(
        self,
        source: TemplateSource,
        target_dir: Path,
        force: bool = False,
    ) -> UpdateResult:
        updater = TemplateUpdater()
        prev_version = updater.get_git_version(target_dir)

        if source.source_type == "git":
            if force and target_dir.is_dir():
                shutil.rmtree(target_dir)
            ok = updater.git_clone_or_pull(
                source.url, target_dir, source.branch,
            )
        else:
            ok = False

        new_version = updater.get_git_version(target_dir) if ok else ""
        count = updater.count_files(target_dir, self.file_patterns)

        return UpdateResult(
            scanner=self.scanner_name,
            source_name=source.name,
            success=ok,
            previous_version=prev_version,
            new_version=new_version,
            templates_added=count,
            error="" if ok else "Update failed",
        )

    def get_scanner_options(
        self,
        template_dir: Path,
        sources: list[TemplateSource],
    ) -> dict[str, Any]:
        """Wapiti currently has limited external template support."""
        return {}


# ------------------------------------------------------------------
# Registry
# ------------------------------------------------------------------

ADAPTER_REGISTRY: dict[str, type[BaseScannerTemplateAdapter]] = {
    "nuclei": NucleiTemplateAdapter,
    "nikto": NiktoTemplateAdapter,
    "nmap": NmapTemplateAdapter,
    "wapiti": WapitiTemplateAdapter,
}


def get_adapter(scanner_name: str) -> BaseScannerTemplateAdapter | None:
    """Instantiate the template adapter for *scanner_name*, or None."""
    cls = ADAPTER_REGISTRY.get(scanner_name)
    return cls() if cls else None
