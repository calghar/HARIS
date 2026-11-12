import functools
import re
from enum import StrEnum
from typing import Any

import yaml
from pydantic import BaseModel, Field, field_validator

from ..config.paths import resolve_config_file

VERIFY_FILE = "verify.yaml"


class VerifyMode(StrEnum):
    OFF = "off"
    REPLAY = "replay"
    LLM = "llm"


DEFAULT_VERIFY_MODE = VerifyMode.REPLAY


class TimingSettings(BaseModel):
    delay_s: float = Field(default=5.0, gt=0)
    pairs: int = Field(default=3, ge=1)
    min_gap_ratio: float = Field(default=0.8, gt=0, le=1)
    payloads: list[str] = Field(min_length=1)
    cmd_payloads: list[str] = Field(min_length=1)


class LLMVerdictSettings(BaseModel):
    abstain_below: float = Field(default=0.7, ge=0, le=1)
    max_cases: int = Field(default=50, ge=0)
    max_tokens: int | None = Field(default=200_000, ge=1)
    max_cost_usd: float | None = Field(default=2.0, gt=0)
    temperature: float = Field(default=0.0, ge=0)
    max_output_tokens: int = Field(default=800, ge=1)
    request_chars: int = Field(default=4096, ge=1)
    response_headers: list[str] = Field(default_factory=list)


class VerifySettings(BaseModel):
    max_requests: int = Field(default=500, ge=1)
    request_timeout_s: float = Field(default=10.0, gt=0)
    poc_max_requests: int = Field(default=20, ge=1)
    timing: TimingSettings
    traversal_payloads: list[str] = Field(min_length=1)
    error_probe: str = Field(min_length=1)
    error_signatures: list[str] = Field(min_length=1)
    header_valid: dict[str, str] = Field(default_factory=dict)
    canary_instruction: str
    llm: LLMVerdictSettings = Field(default_factory=LLMVerdictSettings)

    @field_validator("error_signatures")
    @classmethod
    def _compilable(cls, patterns: list[str]) -> list[str]:
        for pattern in patterns:
            re.compile(pattern)
        return patterns

    @field_validator("header_valid")
    @classmethod
    def _header_patterns(cls, patterns: dict[str, str]) -> dict[str, str]:
        for pattern in patterns.values():
            re.compile(pattern)
        return {name.lower(): pattern for name, pattern in patterns.items()}


@functools.cache
def load_verify_settings() -> VerifySettings:
    raw: dict[str, Any] = (
        yaml.safe_load(resolve_config_file(VERIFY_FILE).read_text("utf-8")) or {}
    )
    return VerifySettings.model_validate(raw)
