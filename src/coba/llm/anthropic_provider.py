"""Anthropic provider — Claude 3.5 family + any Anthropic-compatible endpoint.

When :class:`Settings.anthropic_base_url` is set, requests go to that URL via
``AsyncAnthropic(base_url=...)``. This covers AWS Bedrock proxies, vendor
gateways, and self-hosted Anthropic-compatible relays. ``supports()``
stays strict (only ``claude-*``) because non-Claude models on an
Anthropic-compatible endpoint are rare and ambiguous — prefer the OpenAI
provider with a custom base URL for those.
"""

from __future__ import annotations

import time
from typing import Any

from coba.llm.base import LLMProvider, ProviderUnavailable
from coba.llm.cost import price_for
from coba.utils.logging import get_logger
from coba.utils.schemas import LLMMessage, LLMResponse, LLMUsage, Role

log = get_logger("coba.llm.anthropic")


class AnthropicProvider(LLMProvider):
    name = "anthropic"

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
        return bool(self.api_key)

    def supports(self, model_id: str) -> bool:
        return model_id.startswith("claude-")

    def _get_client(self) -> Any:  # pragma: no cover
        if self._client is None:
            if not self.api_key:
                raise ProviderUnavailable("ANTHROPIC_API_KEY not set")
            try:
                from anthropic import AsyncAnthropic
            except ImportError as exc:
                raise ProviderUnavailable("anthropic package not installed") from exc
            kwargs: dict[str, Any] = {"api_key": self.api_key}
            if self.base_url:
                kwargs["base_url"] = self.base_url
            self._client = AsyncAnthropic(**kwargs)
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

        # Anthropic separates system message into its own param.
        system_parts: list[str] = [m.content for m in messages if m.role == Role.SYSTEM]
        user_msgs = [
            {"role": m.role.value, "content": m.content} for m in messages if m.role != Role.SYSTEM
        ]

        # If json_mode requested, append a strict-JSON nudge to system.
        if json_mode:
            system_parts.append("Respond with a single valid JSON object only. No prose.")

        t0 = time.perf_counter()
        resp = await client.messages.create(
            model=model_id,
            system="\n\n".join(system_parts) if system_parts else None,
            messages=user_msgs,
            temperature=temperature,
            max_tokens=max_tokens,
        )
        latency = time.perf_counter() - t0

        text = "".join(block.text for block in resp.content if getattr(block, "text", None))
        usage = LLMUsage(
            prompt_tokens=resp.usage.input_tokens if resp.usage else 0,
            completion_tokens=resp.usage.output_tokens if resp.usage else 0,
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
