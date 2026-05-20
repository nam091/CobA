"""OpenAI provider — GPT-4o, GPT-4o-mini, or any OpenAI-compatible endpoint.

When :class:`Settings.openai_base_url` is set, the provider:

* sends requests to the custom base URL via ``AsyncOpenAI(base_url=...)``;
* relaxes :meth:`supports` so arbitrary model ids (e.g. ``qwen2.5-coder``,
  ``meta-llama/Llama-3.1-8B-Instruct``, ``deepseek-coder``) are accepted as
  long as they are NOT obviously another vendor's namespace
  (``claude-*``, ``gemini-*``);
* defaults to ``api_key="sk-noauth"`` so providers that don't require a
  key (e.g. vLLM on a private network) still get a non-empty header.

This pattern matches LiteLLM and OpenAI's own client and covers most of
the "OpenAI-compatible API" ecosystem (OpenRouter, Together, Groq,
Fireworks, DeepSeek, Mistral, Ollama's ``/v1`` shim, vLLM, ...).
"""

from __future__ import annotations

import time
from typing import Any

from coba.llm.base import LLMProvider, ProviderUnavailable
from coba.llm.cost import price_for
from coba.utils.logging import get_logger
from coba.utils.schemas import LLMMessage, LLMResponse, LLMUsage

log = get_logger("coba.llm.openai")

_OPENAI_MODELS = {"gpt-4o", "gpt-4o-mini", "gpt-4o-2024-08-06"}
_OTHER_VENDOR_PREFIXES = ("claude-", "gemini-")


class OpenAIProvider(LLMProvider):
    name = "openai"

    def __init__(
        self,
        api_key: str | None,
        *,
        base_url: str | None = None,
    ) -> None:
        self.api_key = api_key
        self.base_url = base_url
        self._client: Any = None

    def available(self) -> bool:
        # With a custom base_url, an API key may be optional (e.g. private
        # vLLM or Ollama). Without a base_url we need a real OpenAI key.
        if self.base_url:
            return True
        return bool(self.api_key)

    def supports(self, model_id: str) -> bool:
        if model_id in _OPENAI_MODELS or model_id.startswith("gpt-"):
            return True
        if self.base_url:
            # Custom endpoint — accept anything that isn't another vendor's
            # well-known namespace. The router still falls back gracefully
            # if the endpoint rejects the id.
            return not any(model_id.startswith(p) for p in _OTHER_VENDOR_PREFIXES)
        return False

    def _get_client(self) -> Any:  # pragma: no cover - thin wrapper
        if self._client is None:
            api_key = self.api_key or ("sk-noauth" if self.base_url else None)
            if not api_key:
                raise ProviderUnavailable("OPENAI_API_KEY not set")
            try:
                from openai import AsyncOpenAI
            except ImportError as exc:
                raise ProviderUnavailable("openai package not installed") from exc
            kwargs: dict[str, Any] = {"api_key": api_key}
            if self.base_url:
                kwargs["base_url"] = self.base_url
            self._client = AsyncOpenAI(**kwargs)
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
        kwargs: dict[str, Any] = {
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
        # Custom endpoints often don't have a price entry — ``price_for``
        # falls back to zero, which is the safest default for self-hosted.
        cost = price_for(model_id).compute(usage)
        return LLMResponse(
            text=text,
            model=model_id,
            provider=self.name,
            usage=usage,
            cost_usd=cost,
            latency_seconds=latency,
        )
