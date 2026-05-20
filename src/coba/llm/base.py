"""Base classes for LLM providers."""

from __future__ import annotations

from abc import ABC, abstractmethod
from enum import Enum

from coba.utils.schemas import LLMMessage, LLMResponse


class TaskKind(str, Enum):
    DETECTOR = "detector"
    VERIFIER = "verifier"
    EMBEDDER = "embedder"
    HEAVY_EVAL = "heavy_eval"


class ProviderUnavailable(RuntimeError):
    """Raised when a provider's API key is missing or endpoint is unreachable."""


class BudgetExceeded(RuntimeError):
    """Raised when the daily LLM budget is exhausted."""


class LLMProvider(ABC):
    """Provider-abstract base.

    Each provider knows how to:
    - check availability (api key / health),
    - run a single completion call,
    - report the model's input/output price per 1M tokens.
    """

    name: str = "abstract"

    @abstractmethod
    def available(self) -> bool:
        """Return True if this provider can serve requests."""

    @abstractmethod
    def supports(self, model_id: str) -> bool:
        """Return True if this provider serves the given model id."""

    @abstractmethod
    async def complete(
        self,
        model_id: str,
        messages: list[LLMMessage],
        *,
        temperature: float = 0.0,
        max_tokens: int = 1024,
        json_mode: bool = False,
    ) -> LLMResponse:
        """Run a single chat completion."""
