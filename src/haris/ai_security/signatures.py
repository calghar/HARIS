import functools
from typing import Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field

from ..config.paths import resolve_config_file
from ..models import Severity

SIGNATURES_FILE = "ai_signatures.yaml"


class Signature(BaseModel):
    """One probe: where to ask, and which body validator decides a hit."""

    model_config = ConfigDict(frozen=True)

    id: str
    label: str
    method: Literal["GET", "HEAD", "POST"] = "GET"
    path: str
    validator: str
    capability: Literal["chat", "admin", "mcp", "info"]
    chat_path: str = ""
    exposure_severity: Severity | None = None
    rpc: str = ""


class Pattern(BaseModel):
    model_config = ConfigDict(frozen=True)

    id: str
    label: str
    pattern: str


class McpRules(BaseModel):
    model_config = ConfigDict(frozen=True)

    protocol_version: str
    max_pages: int
    instruction_patterns: list[str]
    free_form_params: list[str]
    read_verbs: list[str]
    private_nouns: list[str]
    send_verbs: list[str]


class SignatureFile(BaseModel):
    model_config = ConfigDict(frozen=True)

    signatures: list[Signature]
    mcp: McpRules
    provider_keys: list[Pattern]
    min_key_entropy: float
    system_prompt_patterns: list[str] = Field(default_factory=list)
    llm_settings_patterns: list[str] = Field(default_factory=list)
    error_signatures: list[str] = Field(default_factory=list)
    widgets: list[Pattern] = Field(default_factory=list)


@functools.cache
def load_signatures() -> SignatureFile:
    """Load ``ai_signatures.yaml`` (``./config`` override, else packaged)."""
    with open(resolve_config_file(SIGNATURES_FILE), encoding="utf-8") as fh:
        return SignatureFile.model_validate(yaml.safe_load(fh))
