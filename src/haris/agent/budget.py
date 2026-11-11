import time
from collections.abc import Callable

from ..llm.budget import LLMBudget
from ..llm.settings import BudgetSettings
from .settings import AgentSettings


class JobBudget:
    """Per-job tool-call, token and wall-clock caps. Cost sits on ``llm``."""

    def __init__(
        self,
        settings: AgentSettings,
        clock: Callable[[], float] = time.monotonic,
        *,
        llm: LLMBudget | None = None,
    ) -> None:
        self.settings = settings
        self.clock = clock
        self.llm = llm
        self.started = clock()
        self.tool_calls = 0
        self.tokens = 0

    def check_clock(self) -> str:
        if self.clock() - self.started > self.settings.wall_clock_s:
            return "wall_clock"
        return ""

    def charge_tokens(self, usage: dict[str, int]) -> str:
        self.tokens += int(usage.get("total_tokens", 0))
        if self.tokens > self.settings.max_tokens:
            return "tokens"
        return ""

    def request_tool(self) -> str:
        """Count one requested tool call. The call past the cap is not run."""
        self.tool_calls += 1
        if self.tool_calls > self.settings.max_tool_calls:
            return "tool_calls"
        return ""


def llm_budget(settings: AgentSettings, *, remaining_cost: float) -> LLMBudget:
    """Token cap for one job; cost cap is what the scan has left."""
    return LLMBudget(
        BudgetSettings(
            max_tokens=settings.max_tokens,
            max_cost_usd=max(remaining_cost, 0.01),
        )
    )
