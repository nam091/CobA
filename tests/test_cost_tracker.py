"""Unit tests for ``coba.llm.cost``."""

from coba.llm.cost import MODEL_PRICES, CostTracker, price_for
from coba.utils.schemas import LLMUsage


def test_known_model_has_price() -> None:
    assert "gpt-4o-mini" in MODEL_PRICES
    p = price_for("gpt-4o-mini")
    assert p.input_per_million > 0
    assert p.output_per_million > 0


def test_unknown_model_zero_price() -> None:
    p = price_for("not-a-real-model")
    assert p.input_per_million == 0.0


def test_cost_tracker_record_and_budget() -> None:
    t = CostTracker(daily_budget_usd=1.0)
    usage = LLMUsage(prompt_tokens=1_000_000, completion_tokens=0)
    cost = t.record("gpt-4o-mini", "detector", usage)
    assert cost == 0.15
    assert t.spent == 0.15
    assert t.within_budget()
    # Exceed budget
    big = LLMUsage(prompt_tokens=10_000_000, completion_tokens=0)
    t.record("gpt-4o-mini", "detector", big)
    assert not t.within_budget()


def test_summary_shape() -> None:
    t = CostTracker(daily_budget_usd=5.0)
    t.record("gpt-4o-mini", "detector", LLMUsage(prompt_tokens=1000))
    s = t.summary()
    assert "total_usd" in s
    assert "by_model" in s
    assert "by_task" in s
    assert s["by_model"]["gpt-4o-mini"] > 0
