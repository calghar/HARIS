import re
from fnmatch import fnmatchcase
from pathlib import Path
from typing import Literal, Self
from urllib.parse import unquote, urlsplit

import yaml
from pydantic import AnyHttpUrl, BaseModel, ConfigDict, Field, model_validator

CWE_PATTERN = r"^CWE-\d+$"


def normalise_path(url: str) -> str:
    """Path of a URL or path pattern: no scheme, host, query or trailing slash."""
    path = re.sub(r"/{2,}", "/", unquote(urlsplit(url.strip()).path))
    return "/" + path.strip("/")


def normalise_cwe(cwe: object) -> str:
    """`"79"`, `"cwe-79"` and `79` all become `CWE-79`; anything else becomes ``."""
    match = re.fullmatch(r"(?i)(?:cwe-)?(\d+)", str(cwe or "").strip())
    return f"CWE-{match.group(1)}" if match else ""


class TruthEntry(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str
    method: str
    url: str = Field(description="Path glob matched against the normalised finding URL")
    parameter: str = ""
    vuln_class: str = Field(description="Class token glob; a CWE token matches `cwe`")
    cwe: str = Field(pattern=CWE_PATTERN)
    expected: Literal["true_positive"]
    source: AnyHttpUrl | None = None
    notes: str = ""

    def matches(self, class_token: str, path: str, parameter: str) -> bool:
        return (
            (fnmatchcase(class_token, self.vuln_class) or class_token == self.cwe)
            and fnmatchcase(path, normalise_path(self.url))
            and parameter == self.parameter
        )


class IgnoreEntry(BaseModel):
    """A finding that is neither a true nor a false positive; scoring skips it."""

    model_config = ConfigDict(extra="forbid")

    vuln_class: str = Field(description="Class token glob")
    url: str = Field(description="Path glob matched against the normalised finding URL")
    parameter: str | None = Field(
        default=None, description="Matches any parameter when omitted"
    )
    reason: str = Field(min_length=1)

    def matches(self, class_token: str, path: str, parameter: str) -> bool:
        return (
            fnmatchcase(class_token, self.vuln_class)
            and fnmatchcase(path, normalise_path(self.url))
            and (self.parameter is None or parameter == self.parameter)
        )


class GroundTruth(BaseModel):
    model_config = ConfigDict(extra="forbid")

    target: str
    kind: Literal["fixture", "external"]
    entries: list[TruthEntry]
    ignore: list[IgnoreEntry] = Field(default_factory=list)

    @model_validator(mode="after")
    def _check_entries(self) -> Self:
        ids = [entry.id for entry in self.entries]
        if len(ids) != len(set(ids)):
            raise ValueError(f"{self.target}: duplicate entry ids")
        if self.kind == "external":
            missing = [entry.id for entry in self.entries if entry.source is None]
            if missing:
                raise ValueError(f"{self.target}: entries without source: {missing}")
        return self


def load_ground_truth(path: Path) -> GroundTruth:
    return GroundTruth.model_validate(yaml.safe_load(path.read_text()))
