"""Configuration data models."""

from typing import Any

from pydantic import BaseModel, Field

from .target import Target
from .templates import TemplateConfig, TemplateSource


class ScannerConfig(BaseModel):
    """Configuration for a single scanner."""

    name: str
    enabled: bool = True
    options: dict[str, Any] = Field(default_factory=dict)


class LLMConfig(BaseModel):
    """Configuration for LLM-powered analysis features."""

    backend: str = "anthropic"
    model: str = ""
    enrichment_enabled: bool = False
    enrich_severity_threshold: str = "high"
    max_tokens_per_finding: int = 1024
    triage_context: dict[str, Any] = Field(default_factory=dict)
    model_routing: dict[str, str] = Field(default_factory=dict)
    """Map task type to model override.

    Keys: summary, explain, remediation, enrichment,
          attack_chains, triage, chat
    Values: model name (e.g. 'claude-haiku-4-5')
    """


class Config(BaseModel):
    """Top-level configuration for a scan session."""

    target: Target
    scanners: list[ScannerConfig] = Field(default_factory=list)
    profile: str = "full"
    output_dir: str = "./reports"
    report_formats: list[str] = Field(
        default_factory=lambda: ["markdown", "json"]
    )
    log_level: str = "INFO"

    # Template management
    template_dir: str = "./templates"
    template_sources: list[TemplateSource] = Field(default_factory=list)

    # LLM analysis
    llm: LLMConfig = Field(default_factory=LLMConfig)

    @property
    def enabled_scanners(self) -> list[ScannerConfig]:
        return [s for s in self.scanners if s.enabled]

    @property
    def template_config(self) -> TemplateConfig:
        """Build a TemplateConfig from the flat config fields."""
        return TemplateConfig(
            template_dir=self.template_dir,
            sources=self.template_sources,
        )
