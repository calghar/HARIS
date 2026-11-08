import functools
import re
from typing import Any, Literal

import yaml
from pydantic import BaseModel, Field

from ..config.paths import resolve_config_file
from ..models import Finding

VULN_CLASSES_FILE = "vuln_classes.yaml"
BUILTIN_SOURCE = "builtin"


class VulnClass(BaseModel):
    id: str
    primary_cwe: str
    granularity: Literal["host", "path", "parameter"]
    oracle: str = "none"
    aliases: dict[str, list[str]] = Field(default_factory=dict)


class VulnClassRegistry:
    """Canonical vulnerability classes and the aliases that map findings to them."""

    def __init__(self, classes: list[VulnClass], external_scanners: list[str]) -> None:
        self.classes = {c.id: c for c in classes}
        self._external = frozenset(external_scanners)
        self._patterns: dict[str, list[tuple[re.Pattern[str], str]]] = {}
        for cls in classes:
            for source, aliases in cls.aliases.items():
                patterns = self._patterns.setdefault(source, [])
                patterns.extend((re.compile(a, re.IGNORECASE), cls.id) for a in aliases)

    def classify(self, finding: Finding) -> str:
        """Return the class id for *finding*, or an ``unclassified:`` id."""
        if finding.vuln_class:
            return finding.vuln_class
        scanner = finding.scanner.lower()
        source = scanner if scanner in self._external else BUILTIN_SOURCE
        exact = [*finding.tags, str(finding.raw_data.get("template-id", ""))]
        for pattern, class_id in self._patterns.get(source, []):
            if pattern.match(finding.title) or any(
                pattern.fullmatch(t) for t in exact if t
            ):
                return class_id
        return f"unclassified:{scanner or 'unknown'}:{slug(finding.title)}"


def slug(text: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-")


@functools.cache
def get_registry() -> VulnClassRegistry:
    """Load the registry from ``vuln_classes.yaml`` (cached per process)."""
    with open(resolve_config_file(VULN_CLASSES_FILE), encoding="utf-8") as fh:
        raw: dict[str, Any] = yaml.safe_load(fh)
    return VulnClassRegistry(
        [VulnClass.model_validate(c) for c in raw["classes"]],
        raw.get("external_scanners", []),
    )
