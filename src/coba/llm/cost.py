"""LLM cost tracking and price table."""

from __future__ import annotations

import threading
from collections import defaultdict
from dataclasses import dataclass, field

from coba.utils.logging import get_logger
from coba.utils.schemas import LLMUsage

log = get_logger("coba.llm.cost")


@dataclass(frozen=True)
class ModelPrice:
    """USD per 1M tokens."""

    input_per_million: float
    output_per_million: float

    def compute(self, usage: LLMUsage) -> float:
        return (
            usage.prompt_tokens * self.input_per_million / 1_000_000.0
            + usage.completion_tokens * self.output_per_million / 1_000_000.0
        )


# Source: provider pricing pages as of 2025-01. Update when prices change.
MODEL_PRICES: dict[str, ModelPrice] = {
    # OpenAI
    "gpt-4o": ModelPrice(2.50, 10.00),
    "gpt-4o-mini": ModelPrice(0.15, 0.60),
    "gpt-4o-2024-08-06": ModelPrice(2.50, 10.00),
    # Anthropic
    "claude-3-5-sonnet-20241022": ModelPrice(3.00, 15.00),
    "claude-3-5-haiku-20241022": ModelPrice(0.80, 4.00),
    "claude-3-opus-20240229": ModelPrice(15.00, 75.00),
    # Google
    "gemini-1.5-flash": ModelPrice(0.075, 0.30),
    "gemini-1.5-pro": ModelPrice(1.25, 5.00),
    # Local (free at API level — GPU cost amortized separately)
    "qwen2.5-coder:7b": ModelPrice(0.0, 0.0),
    "qwen2.5-coder:32b": ModelPrice(0.0, 0.0),
    "deepseek-coder-v2:16b": ModelPrice(0.0, 0.0),
    "llama3.1:8b": ModelPrice(0.0, 0.0),
    "codellama:13b": ModelPrice(0.0, 0.0),
}


def price_for(model_id: str) -> ModelPrice:
    return MODEL_PRICES.get(model_id, ModelPrice(0.0, 0.0))


@dataclass
class CostTracker:
    """Thread-safe daily cost ledger with budget cap."""

    daily_budget_usd: float = 5.0
    _spent: float = 0.0
    _by_model: dict[str, float] = field(default_factory=lambda: defaultdict(float))
    _by_task: dict[str, float] = field(default_factory=lambda: defaultdict(float))
    _lock: threading.Lock = field(default_factory=threading.Lock)

    def record(self, model_id: str, task: str, usage: LLMUsage) -> float:
        cost = price_for(model_id).compute(usage)
        with self._lock:
            self._spent += cost
            self._by_model[model_id] += cost
            self._by_task[task] += cost
        log.debug(
            "cost.record",
            model=model_id,
            task=task,
            cost=cost,
            spent=self._spent,
            budget=self.daily_budget_usd,
        )
        return cost

    @property
    def spent(self) -> float:
        return self._spent

    def within_budget(self) -> bool:
        return self._spent < self.daily_budget_usd

    def remaining(self) -> float:
        return max(0.0, self.daily_budget_usd - self._spent)

    def summary(self) -> dict[str, float | dict[str, float]]:
        with self._lock:
            return {
                "total_usd": round(self._spent, 4),
                "budget_usd": self.daily_budget_usd,
                "remaining_usd": round(self.remaining(), 4),
                "by_model": {k: round(v, 4) for k, v in self._by_model.items()},
                "by_task": {k: round(v, 4) for k, v in self._by_task.items()},
            }
