import functools
from typing import Any

import yaml
from pydantic import BaseModel, Field

from ..config.paths import resolve_config_file

AGENT_FILE = "agent.yaml"
DEFAULT_CLASSES = (
    "xss_reflected",
    "sqli_error",
    "sqli_time",
    "path_traversal",
    "open_redirect",
    "ssrf",
)


class AgentSettings(BaseModel):
    classes: list[str] = Field(default_factory=lambda: list(DEFAULT_CLASSES))
    max_tool_calls: int = Field(default=40, ge=1)
    max_tokens: int = Field(default=300_000, ge=1)
    wall_clock_s: float = Field(default=600, gt=0)
    max_jobs: int = Field(default=10, ge=0)
    max_cost_usd: float = Field(default=10.0, gt=0)
    max_requests: int = Field(default=300, ge=1)
    rate_limit_rps: float = Field(default=2.0, gt=0)
    guardrail_abort_at: int = Field(default=3, ge=1)
    min_severity: str = "medium"
    image: str = "haris-agent-sandbox"
    memory: str = "512m"
    cpus: str = "1"
    pids_limit: int = 128
    sandbox_user: str = "65534:65534"
    work_tmpfs: str = "64m"
    tmp_tmpfs: str = "16m"


@functools.cache
def load_agent_settings() -> AgentSettings:
    raw: dict[str, Any] = (
        yaml.safe_load(resolve_config_file(AGENT_FILE).read_text("utf-8")) or {}
    )
    return AgentSettings.model_validate(raw)
