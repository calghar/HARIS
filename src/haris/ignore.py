import fnmatch
import logging
import re
from collections.abc import Iterable
from datetime import date
from pathlib import Path
from typing import Literal, Self

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError, model_validator

from .core.identity import identify, normalise_url
from .models import Finding, Suppression

logger = logging.getLogger(__name__)

DEFAULT_IGNORE_FILE = ".haris-ignore.yaml"
_FINGERPRINT = re.compile(r"[0-9a-f]{64}")


class IgnoreError(ValueError):
    """The ignore or baseline file cannot be used (CLI exit code 3)."""


class IgnoreEntry(BaseModel):
    model_config = ConfigDict(extra="forbid")

    fingerprint: str | None = None
    rule: str | None = None
    url: str | None = None
    reason: str = Field(min_length=1)
    expires: date
    author: str = Field(min_length=1)

    @model_validator(mode="after")
    def _one_selector(self) -> Self:
        if (self.fingerprint is None) == (self.rule is None):
            raise ValueError("exactly one of fingerprint or rule is required")
        if self.fingerprint is not None and not _FINGERPRINT.fullmatch(
            self.fingerprint
        ):
            raise ValueError("fingerprint must be 64 lowercase hex characters")
        if self.url is not None and self.rule is None:
            raise ValueError("url is only valid together with rule")
        return self

    def matches(self, finding: Finding, base_url: str) -> bool:
        class_id, fingerprint = (
            (finding.vuln_class, finding.fingerprint)
            if finding.fingerprint
            else identify(finding, base_url)
        )
        if self.fingerprint is not None:
            return fingerprint == self.fingerprint
        if class_id != self.rule:
            return False
        return self.url is None or fnmatch.fnmatchcase(
            normalise_url(finding.url, base_url), self.url
        )


class IgnoreFile(BaseModel):
    model_config = ConfigDict(extra="forbid")

    version: Literal[1]
    ignores: list[IgnoreEntry] = Field(default_factory=list)


def load_ignore_file(path: Path) -> IgnoreFile:
    """Parse and validate *path*; raise IgnoreError on any problem."""
    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
        return IgnoreFile.model_validate(raw)
    except (OSError, yaml.YAMLError, ValidationError) as exc:
        raise IgnoreError(f"invalid ignore file {path}: {exc}") from exc


def apply_ignores(
    findings: Iterable[Finding],
    ignore: IgnoreFile,
    *,
    base_url: str,
    today: date | None = None,
) -> int:
    """Set ``suppression`` on matching findings of any tier; return the count.

    Expired entries match nothing and log a warning.
    """
    today = today or date.today()
    live: list[IgnoreEntry] = []
    for entry in ignore.ignores:
        if entry.expires < today:
            logger.warning(
                "Ignore entry %s expired on %s and suppresses nothing",
                entry.fingerprint or entry.rule,
                entry.expires,
            )
        else:
            live.append(entry)

    suppressed = 0
    for finding in findings:
        hit = next((e for e in live if e.matches(finding, base_url)), None)
        if hit is not None:
            finding.suppression = Suppression(
                reason=hit.reason,
                author=hit.author,
                expires=hit.expires.isoformat(),
            )
            suppressed += 1
    return suppressed
