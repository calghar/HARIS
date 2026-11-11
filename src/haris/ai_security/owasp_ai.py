import functools
import re

import yaml
from pydantic import BaseModel, ConfigDict, Field, model_validator

from ..config.paths import resolve_config_file
from ..core.owasp import AI_RISKS
from ..models import OwaspCategory, Severity, VerificationOracle

MAPPINGS_FILE = "ai_mappings.yaml"
DEFAULT_KEY = "default"
_PREFIX = re.compile(r"[A-Z]+")
WEB_RISKS = {c.value.split(" - ")[0]: c.value for c in OwaspCategory}


def _prefix(risk_id: str) -> str:
    match = _PREFIX.match(risk_id)
    return match.group() if match else ""


def risk_label(risk_id: str) -> str:
    """``LLM01:2026`` -> ``LLM01:2026 - Prompt Injection`` (web ids included)."""
    known = AI_RISKS.get(risk_id)
    return known.value if known else WEB_RISKS[risk_id]


class CheckMapping(BaseModel):
    model_config = ConfigDict(frozen=True)

    title: str
    description: str
    severity: Severity
    owasp: list[str]
    cwe: str
    confidence: float = Field(ge=0.0, le=1.0)
    oracle: VerificationOracle
    remediation: str


class ToolMapping(BaseModel):
    model_config = ConfigDict(frozen=True)

    owasp: list[str]
    cwe: str
    severity: Severity


class Mappings(BaseModel):
    model_config = ConfigDict(frozen=True)

    references: dict[str, str]
    checks: dict[str, CheckMapping]
    garak: dict[str, ToolMapping]
    promptfoo: dict[str, ToolMapping]

    @model_validator(mode="after")
    def _known_ids(self) -> "Mappings":
        ids = [i for c in self.checks.values() for i in c.owasp]
        ids += [
            i for t in (self.garak, self.promptfoo) for m in t.values() for i in m.owasp
        ]
        unknown = sorted({i for i in ids if i not in AI_RISKS and i not in WEB_RISKS})
        if unknown:
            raise ValueError(f"unknown OWASP ids in {MAPPINGS_FILE}: {unknown}")
        for tool, table in (("garak", self.garak), ("promptfoo", self.promptfoo)):
            if DEFAULT_KEY not in table:
                raise ValueError(f"{tool} table in {MAPPINGS_FILE} needs a default")
        return self

    def tool_mapping(self, tool: str, key: str) -> ToolMapping:
        """The mapping for a garak module or promptfoo plugin, else the tool default."""
        table = self.garak if tool == "garak" else self.promptfoo
        return table.get(key, table[DEFAULT_KEY])

    def reference_urls(self, ids: list[str]) -> list[str]:
        """Source URLs for the lists the ids belong to (``LLM``, ``ASI``, ``MCP``)."""
        prefixes = dict.fromkeys(_prefix(i) for i in ids)
        return [self.references[p] for p in prefixes if p in self.references]


@functools.cache
def load_mappings() -> Mappings:
    """Load ``ai_mappings.yaml`` (``./config`` override, else packaged)."""
    with open(resolve_config_file(MAPPINGS_FILE), encoding="utf-8") as fh:
        return Mappings.model_validate(yaml.safe_load(fh))
