import functools
import secrets

import yaml
from pydantic import BaseModel, ConfigDict, Field

from ..config.paths import packaged_config_dir

PROBES_FILE = "ai_probes.yaml"
CANARY_PREFIX = "HARIS-CANARY-"
CANARY_BYTES = 8
MARKER_TOKEN_BYTES = 6


class Limits(BaseModel):
    model_config = ConfigDict(frozen=True)

    max_prompts: int = Field(gt=0)
    max_tokens_per_prompt: int = Field(gt=0)
    burst_requests: int = Field(gt=0)
    system_prompt_markers: list[str] = Field(default_factory=list)


class Prompt(BaseModel):
    model_config = ConfigDict(frozen=True)

    id: str
    content: str
    kind: str = ""


class Control(BaseModel):
    content: str


class TokenCap(BaseModel):
    content: str
    max_tokens: int = Field(gt=0)
    chars_per_token: int = Field(gt=0)


class Consumption(BaseModel):
    burst: Control
    max_tokens: TokenCap


class Sink(BaseModel):
    model_config = ConfigDict(frozen=True)

    path: str
    param: str


class Xss(BaseModel):
    marker: str
    sinks: list[Sink]


class ProbeFile(BaseModel):
    model_config = ConfigDict(frozen=True)

    ai: Limits
    control: Control
    probes: list[Prompt]
    jailbreaks: list[Prompt]
    consumption: Consumption
    xss: Xss


@functools.cache
def load_probes() -> ProbeFile:
    """Load the packaged ``ai_probes.yaml``; no ``./config`` override exists."""
    with open(packaged_config_dir() / PROBES_FILE, encoding="utf-8") as fh:
        return ProbeFile.model_validate(yaml.safe_load(fh))


def new_canary() -> str:
    return CANARY_PREFIX + secrets.token_hex(CANARY_BYTES)


def new_marker(template: str) -> str:
    return template.format(token=secrets.token_hex(MARKER_TOKEN_BYTES))
