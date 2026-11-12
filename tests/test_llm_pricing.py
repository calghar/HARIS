import pytest

from haris.llm.budget import MILLION, BudgetExceededError, LLMBudget, Reservation
from haris.llm.settings import BudgetSettings, Price, load_settings

TABLE_INPUT_PER_MTOK = 3.0
TABLE_OUTPUT_PER_MTOK = 6.0


def table(model: str, prompt: int, output: int) -> float | None:
    """A LiteLLM table that prices only bedrock/x at 3.0 in, 6.0 out per Mtok."""
    if model != "bedrock/x":
        return None
    return (prompt * TABLE_INPUT_PER_MTOK + output * TABLE_OUTPUT_PER_MTOK) / MILLION


@pytest.fixture(autouse=True)
def litellm_table(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("haris.llm.litellm_backend.table_cost", table)


def budget(
    config_price: float | None,
    *,
    max_tokens: int | None = None,
    max_cost_usd: float | None = None,
) -> LLMBudget:
    pricing = (
        []
        if config_price is None
        else [Price(match="*", input_per_mtok=config_price, output_per_mtok=0.0)]
    )
    settings = load_settings().model_copy(update={"pricing": pricing})
    caps = BudgetSettings(max_tokens=max_tokens, max_cost_usd=max_cost_usd)
    return LLMBudget(caps, settings)


def settled_cost(model: str, config_price: float | None) -> float:
    spend = budget(config_price)
    reservation = Reservation(prompt_tokens=MILLION, max_tokens=0, model=model)
    spend.settle(reservation, {"prompt_tokens": MILLION, "completion_tokens": 0})
    return spend.used_cost


class TestPriceOrder:
    @pytest.mark.parametrize(
        ("model", "config_price", "cost"),
        [
            ("openai/alias", 2.0, 2.0),
            ("bedrock/x", 2.0, 2.0),
            ("bedrock/x", None, 3.0),
            ("openai/alias", None, 0.0),
        ],
        ids=["config-only", "config-beats-table", "table-only", "no-price"],
    )
    def test_recorded_cost(self, model, config_price, cost):
        assert settled_cost(model, config_price) == pytest.approx(cost)

    def test_unpriced_model_is_limited_by_the_token_cap_alone(self):
        spend = budget(None, max_tokens=100_000, max_cost_usd=0.01)
        with pytest.raises(BudgetExceededError):
            spend.reserve(150_000, 1000, "openai/alias")
        assert spend.reserve(1000, 1000, "openai/alias").cost == 0.0

    def test_table_price_limits_output_tokens_to_the_cost_cap(self):
        spend = budget(None, max_cost_usd=0.0035)
        granted = spend.reserve(0, 4000, "bedrock/x").max_tokens
        assert granted == 583  # 0.0035 USD at 6.0 per Mtok output
