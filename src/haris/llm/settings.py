import functools
import re
from fnmatch import fnmatchcase
from typing import Any

import yaml
from pydantic import BaseModel, Field, field_validator

from ..config.paths import resolve_config_file

SETTINGS_FILE = "llm_models.yaml"


class ProviderModels(BaseModel):
    default: str
    fallbacks: list[str] = Field(default_factory=list)


class Capability(BaseModel):
    match: str
    token_param: str = "max_tokens"
    temperature: bool = True
    json_schema: bool = False
    json_object: bool = False


class Price(BaseModel):
    match: str
    input_per_mtok: float = Field(ge=0)
    output_per_mtok: float = Field(ge=0)


class RuntimeSettings(BaseModel):
    timeout_s: float = Field(default=60, gt=0)
    max_retries: int = Field(default=3, ge=0)
    backoff_base_s: float = Field(default=1.0, ge=0)
    backoff_max_s: float = Field(default=30.0, ge=0)
    max_retry_after_s: float = Field(default=120.0, ge=0)
    max_concurrency: int = Field(default=4, ge=1)
    chars_per_token: int = Field(default=4, ge=1)
    min_output_tokens: int = Field(default=64, ge=1)


class BudgetSettings(BaseModel):
    max_tokens: int | None = Field(default=200_000, ge=1)
    max_cost_usd: float | None = Field(default=2.0, gt=0)


class RedactionSettings(BaseModel):
    emails: bool = False
    extra_patterns: list[str] = Field(default_factory=list)

    @field_validator("extra_patterns")
    @classmethod
    def _compilable(cls, patterns: list[str]) -> list[str]:
        for pattern in patterns:
            try:
                re.compile(pattern)
            except re.error as exc:
                raise ValueError(
                    f"invalid redaction pattern {pattern!r}: {exc}"
                ) from exc
        return patterns


class Limits(BaseModel):
    batch_size: int = Field(default=30, ge=1)
    retrieval_threshold: int = Field(default=15, ge=1)
    title: int = Field(default=200, ge=1)
    description: int = Field(default=500, ge=1)
    evidence: int = Field(default=500, ge=1)


class LLMSettings(BaseModel):
    providers: dict[str, ProviderModels]
    capabilities: dict[str, list[Capability]] = Field(default_factory=dict)
    pricing: list[Price] = Field(default_factory=list)
    runtime: RuntimeSettings = Field(default_factory=RuntimeSettings)
    budget: BudgetSettings = Field(default_factory=BudgetSettings)
    redaction: RedactionSettings = Field(default_factory=RedactionSettings)
    limits: Limits = Field(default_factory=Limits)

    def capability(self, provider: str, model: str) -> Capability:
        for entry in self.capabilities.get(provider, []):
            if fnmatchcase(model, entry.match):
                return entry
        return Capability(match="*")

    def price(self, model: str) -> Price | None:
        return next((p for p in self.pricing if fnmatchcase(model, p.match)), None)


@functools.cache
def load_settings() -> LLMSettings:
    raw: dict[str, Any] = (
        yaml.safe_load(resolve_config_file(SETTINGS_FILE).read_text("utf-8")) or {}
    )
    return LLMSettings.model_validate(raw)
