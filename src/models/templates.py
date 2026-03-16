"""Template management data models.

Defines sources, metadata, and update results for scanner template
management.  The TemplateManager (in src/templates/) uses these models
to track where templates come from and their current state on disk.
"""

from pydantic import BaseModel, Field


class TemplateSource(BaseModel):
    """Describes where templates for a scanner come from.

    A single scanner can have multiple sources (e.g. official templates
    plus a private community repository).
    """

    name: str
    """Unique identifier for this source, e.g. ``"nuclei-official"``."""

    scanner: str
    """Scanner this source belongs to, e.g. ``"nuclei"``."""

    source_type: str = "git"
    """How to fetch templates: ``"git"`` | ``"url"`` | ``"local"``."""

    url: str = ""
    """Git repo URL or HTTP download URL."""

    local_path: str = ""
    """Local path override (used when *source_type* is ``"local"``)."""

    branch: str = "main"
    """Git branch to track (only relevant for ``"git"`` sources)."""

    enabled: bool = True


class TemplateMetadata(BaseModel):
    """Tracks the on-disk state of a fetched template source."""

    source_name: str
    scanner: str
    version: str = ""
    """Git short SHA or file hash representing the current version."""

    last_updated: str = ""
    """ISO-8601 timestamp of the last successful update."""

    template_count: int = 0
    """Number of template files found after the last update."""

    local_path: str = ""
    """Absolute path to the directory containing fetched templates."""


class UpdateResult(BaseModel):
    """Outcome of a single template-update operation."""

    scanner: str
    source_name: str
    success: bool
    previous_version: str = ""
    new_version: str = ""
    templates_added: int = 0
    templates_removed: int = 0
    error: str = ""


class TemplateConfig(BaseModel):
    """Aggregate template configuration for the whole framework.

    Stored under the ``template_dir`` / ``template_sources`` keys of
    the top-level YAML config and parsed by the config loader.
    """

    template_dir: str = "./templates"
    """Root directory where all template trees are stored."""

    sources: list[TemplateSource] = Field(default_factory=list)
    """Ordered list of template sources to manage."""

    auto_update: bool = False
    """Whether to attempt an update before each scan."""

    auto_update_interval_hours: int = 24
    """Minimum hours between automatic updates (ignored if *auto_update* is off)."""
