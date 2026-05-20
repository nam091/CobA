"""OpenAI provider — GPT-4o, GPT-4o-mini, etc."""

from __future__ import annotations

import time

from coba.llm.base import LLMProvider, ProviderUnavailable
from coba.llm.cost import price_for
from coba.utils.logging import get_logger
from coba.utils.schemas import LLMMessage, LLMResponse, LLMUsage

log = get_logger("coba.llm.openai")

_OPENAI_MODELS = {"gpt-4o", "gpt-4o-mini", "gpt-4o-2024-08-06"}


class OpenAIProvider(LLMProvider):
    name = "openai"

    def __init__(self, api_key: str | None) -> None:
        self.api_key = api_key
        self._client = None

    def available(self) -> bool:
        return bool(self.api_key)

    def supports(self, model_id: str) -> bool:
        return model_id in _OPENAI_MODELS or model_id.startswith("gpt-")

    def _get_client(self):  # pragma: no cover - thin wrapper
        if self._client is None:
            if not self.api_key:
                raise ProviderUnavailable("OPENAI_API_KEY not set")
            try:
                from openai import AsyncOpenAI
            except ImportError as exc:
                raise ProviderUnavailable("openai package not installed") from exc
            self._client = AsyncOpenAI(api_key=self.api_key)
        return self._client

    async def complete(
        self,
        model_id: str,
        messages: list[LLMMessage],
        *,
        temperature: float = 0.0,
        max_tokens: int = 1024,
        json_mode: bool = False,
    ) -> LLMResponse:
        client = self._get_client()
        kwargs: dict = {
            "model": model_id,
            "messages": [{"role": m.role.value, "content": m.content} for m in messages],
            "temperature": temperature,
            "max_tokens": max_tokens,
        }
        if json_mode:
            kwargs["response_format"] = {"type": "json_object"}

        t0 = time.perf_counter()
        resp = await client.chat.completions.create(**kwargs)
        latency = time.perf_counter() - t0

        text = resp.choices[0].message.content or ""
        usage = LLMUsage(
            prompt_tokens=resp.usage.prompt_tokens if resp.usage else 0,
            completion_tokens=resp.usage.completion_tokens if resp.usage else 0,
        )
        cost = price_for(model_id).compute(usage)
        return LLMResponse(
            text=text,
            model=model_id,
            provider=self.name,
            usage=usage,
            cost_usd=cost,
            latency_seconds=latency,
        )
