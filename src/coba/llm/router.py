"""LLMRouter — provider-abstract orchestrator with policy + fallback."""

from __future__ import annotations

from dataclasses import dataclass, field

from tenacity import (
    AsyncRetrying,
    retry_if_exception_type,
    stop_after_attempt,
    wait_exponential,
)

from coba.config.settings import Settings, get_settings
from coba.llm.anthropic_provider import AnthropicProvider
from coba.llm.base import BudgetExceeded, LLMProvider, ProviderUnavailable, TaskKind
from coba.llm.cost import CostTracker
from coba.llm.gemini_provider import GeminiProvider
from coba.llm.ollama_provider import OllamaProvider
from coba.llm.openai_provider import OpenAIProvider
from coba.utils.logging import get_logger
from coba.utils.schemas import LLMMessage, LLMResponse

log = get_logger("coba.llm.router")


@dataclass
class RoutePolicy:
    """Which model serves which task, with fallbacks."""

    routes: dict[TaskKind, list[str]] = field(default_factory=dict)

    @classmethod
    def from_settings(cls, settings: Settings) -> RoutePolicy:
        # The verifier fallback prefers a different provider than the detector
        # (anti-confirmation-bias). If detector is OpenAI, verifier fallback is Anthropic.
        return cls(
            routes={
                TaskKind.DETECTOR: [
                    settings.coba_llm_detector,
                    "claude-3-5-haiku-20241022",
                    settings.coba_llm_offline_fallback,
                ],
                TaskKind.VERIFIER: [
                    settings.coba_llm_verifier,
                    "gpt-4o",
                    settings.coba_llm_offline_fallback,
                ],
                TaskKind.HEAVY_EVAL: [
                    "gpt-4o",
                    "claude-3-5-sonnet-20241022",
                ],
                TaskKind.EMBEDDER: ["sentence-transformers/all-MiniLM-L6-v2"],
            }
        )

    def candidates(self, task: TaskKind) -> list[str]:
        return list(self.routes.get(task, []))


class LLMRouter:
    """Single entrypoint for any LLM call in CobA."""

    def __init__(self, settings: Settings | None = None) -> None:
        self.settings = settings or get_settings()
        self.policy = RoutePolicy.from_settings(self.settings)
        self.cost = CostTracker(daily_budget_usd=self.settings.coba_llm_daily_budget_usd)
        self._providers: list[LLMProvider] = [
            OpenAIProvider(self.settings.openai_api_key),
            AnthropicProvider(self.settings.anthropic_api_key),
            GeminiProvider(self.settings.google_api_key),
            OllamaProvider(self.settings.ollama_base_url),
        ]

    # ------------------------------------------------------------------ utils
    def _resolve(self, model_id: str) -> LLMProvider | None:
        for p in self._providers:
            if p.supports(model_id) and p.available():
                return p
        return None

    def _is_cloud(self, model_id: str) -> bool:
        cloud_prefixes = ("gpt-", "claude-", "gemini-")
        return any(model_id.startswith(p) for p in cloud_prefixes)

    # ------------------------------------------------------------------ main
    async def complete(
        self,
        task: TaskKind,
        messages: list[LLMMessage],
        *,
        temperature: float = 0.0,
        max_tokens: int = 1024,
        json_mode: bool = False,
    ) -> LLMResponse:
        """Run a completion for ``task`` against the policy's chain of models.

        Order: policy candidates → first available provider → on error/budget
        fall back to next candidate.
        """
        last_error: Exception | None = None

        candidates = self.policy.candidates(task)
        if self.settings.coba_no_cloud:
            candidates = [m for m in candidates if not self._is_cloud(m)]

        if not candidates:
            raise ProviderUnavailable(f"no model available for task={task}")

        for model_id in candidates:
            provider = self._resolve(model_id)
            if provider is None:
                log.warning("router.skip_unavailable", task=task.value, model=model_id)
                continue

            if not self.cost.within_budget() and self._is_cloud(model_id):
                log.warning("router.budget_exhausted", task=task.value, model=model_id)
                continue

            try:
                async for attempt in AsyncRetrying(
                    stop=stop_after_attempt(3),
                    wait=wait_exponential(multiplier=1, min=1, max=10),
                    retry=retry_if_exception_type((ProviderUnavailable,)),
                    reraise=True,
                ):
                    with attempt:
                        resp = await provider.complete(
                            model_id=model_id,
                            messages=messages,
                            temperature=temperature,
                            max_tokens=max_tokens,
                            json_mode=json_mode,
                        )
                self.cost.record(resp.model, task.value, resp.usage)
                log.info(
                    "router.ok",
                    task=task.value,
                    model=model_id,
                    provider=resp.provider,
                    cost_usd=round(resp.cost_usd, 5),
                    tokens_in=resp.usage.prompt_tokens,
                    tokens_out=resp.usage.completion_tokens,
                    latency=round(resp.latency_seconds, 2),
                )
                return resp
            except (ProviderUnavailable, BudgetExceeded) as exc:
                log.warning("router.failover", task=task.value, model=model_id, error=str(exc))
                last_error = exc
                continue
            except Exception as exc:  # pragma: no cover
                log.error(
                    "router.error",
                    task=task.value,
                    model=model_id,
                    error=str(exc),
                    error_type=type(exc).__name__,
                )
                last_error = exc
                continue

        msg = f"all models for task={task.value} unavailable"
        raise ProviderUnavailable(msg) from last_error
