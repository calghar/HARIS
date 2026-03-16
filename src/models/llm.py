"""LLM response data model."""

from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class LLMResponse(BaseModel):
    """Structured response from an LLM backend."""

    model_config = ConfigDict(frozen=True)

    text: str
    model: str = ""
    usage: dict[str, int] = Field(default_factory=dict)
    raw: dict[str, Any] = Field(default_factory=dict)

    @property
    def token_count(self) -> int:
        return self.usage.get("total_tokens", 0)
