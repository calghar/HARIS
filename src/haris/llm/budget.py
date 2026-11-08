import threading

from pydantic import BaseModel

from .settings import BudgetSettings, LLMSettings, load_settings

MILLION = 1_000_000


class BudgetExceededError(RuntimeError):
    status = "skipped_budget"


class Reservation(BaseModel):
    prompt_tokens: int
    max_tokens: int
    cost: float = 0.0
    model: str = ""


class LLMBudget:
    """Per-scan token and cost cap; calls reserve first, then settle on usage."""

    def __init__(
        self,
        budget: BudgetSettings | None = None,
        settings: LLMSettings | None = None,
    ) -> None:
        self._settings = settings or load_settings()
        cfg = budget or self._settings.budget
        self.max_tokens = cfg.max_tokens
        self.max_cost_usd = cfg.max_cost_usd
        self.used_tokens = 0
        self.used_cost = 0.0
        self._reserved_tokens = 0
        self._reserved_cost = 0.0
        self._in_flight = 0
        self._cond = threading.Condition()

    def _cost(self, model: str, prompt_tokens: int, output_tokens: int) -> float:
        price = self._settings.price(model)
        if price is None:
            return 0.0
        return (
            prompt_tokens * price.input_per_mtok + output_tokens * price.output_per_mtok
        ) / MILLION

    def _grant(self, prompt_tokens: int, max_tokens: int, model: str) -> int:
        """Output tokens that fit the remaining caps; 0 when nothing useful fits."""
        granted = max_tokens
        if self.max_tokens is not None:
            left = self.max_tokens - self.used_tokens - self._reserved_tokens
            granted = min(granted, left - prompt_tokens)
        price = self._settings.price(model)
        if self.max_cost_usd is not None and price is not None:
            left_cost = self.max_cost_usd - self.used_cost - self._reserved_cost
            left_cost -= self._cost(model, prompt_tokens, 0)
            if price.output_per_mtok > 0:
                granted = min(granted, int(left_cost * MILLION / price.output_per_mtok))
            elif left_cost < 0:
                granted = 0
        floor = self._settings.runtime.min_output_tokens
        return granted if granted >= min(floor, max_tokens) else 0

    def reserve(self, prompt_tokens: int, max_tokens: int, model: str) -> Reservation:
        """Wait while in-flight calls may free budget, else raise."""
        with self._cond:
            while True:
                granted = self._grant(prompt_tokens, max_tokens, model)
                if granted > 0:
                    break
                if self._in_flight == 0:
                    raise BudgetExceededError(
                        f"budget exhausted ({self.used_tokens} tokens, "
                        f"${self.used_cost:.4f} used)"
                    )
                self._cond.wait()
            cost = self._cost(model, prompt_tokens, granted)
            self._reserved_tokens += prompt_tokens + granted
            self._reserved_cost += cost
            self._in_flight += 1
            return Reservation(
                prompt_tokens=prompt_tokens,
                max_tokens=granted,
                cost=cost,
                model=model,
            )

    def _release(self, reservation: Reservation) -> None:
        self._reserved_tokens -= reservation.prompt_tokens + reservation.max_tokens
        self._reserved_cost -= reservation.cost
        self._in_flight -= 1

    def settle(self, reservation: Reservation, usage: dict[str, int]) -> None:
        prompt = usage.get("prompt_tokens", reservation.prompt_tokens)
        output = usage.get("completion_tokens", 0)
        with self._cond:
            self._release(reservation)
            self.used_tokens += prompt + output
            self.used_cost += self._cost(reservation.model, prompt, output)
            self._cond.notify_all()

    def release(self, reservation: Reservation) -> None:
        with self._cond:
            self._release(reservation)
            self._cond.notify_all()
