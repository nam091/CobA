"""Google Gemini provider."""

from __future__ import annotations

import time

from coba.llm.base import LLMProvider, ProviderUnavailable
from coba.llm.cost import price_for
from coba.utils.logging import get_logger
from coba.utils.sanitize import count_tokens_estimate
from coba.utils.schemas import LLMMessage, LLMResponse, LLMUsage, Role

log = get_logger("coba.llm.gemini")


class GeminiProvider(LLMProvider):
    name = "google"

    def __init__(self, api_key: str | None) -> None:
        self.api_key = api_key
        self._configured = False

    def available(self) -> bool:
        return bool(self.api_key)

    def supports(self, model_id: str) -> bool:
        return model_id.startswith("gemini-")

    def _configure(self) -> None:  # pragma: no cover
        if self._configured:
            return
        if not self.api_key:
            raise ProviderUnavailable("GOOGLE_API_KEY not set")
        try:
            import google.generativeai as genai
        except ImportError as exc:
            raise ProviderUnavailable("google-generativeai not installed") from exc
        genai.configure(api_key=self.api_key)
        self._configured = True

    async def complete(
        self,
        model_id: str,
        messages: list[LLMMessage],
        *,
        temperature: float = 0.0,
        max_tokens: int = 1024,
        json_mode: bool = False,
    ) -> LLMResponse:  # pragma: no cover
        import google.generativeai as genai

        self._configure()
        model = genai.GenerativeModel(
            model_id,
            system_instruction="\n\n".join(m.content for m in messages if m.role == Role.SYSTEM)
            or None,
            generation_config={
                "temperature": temperature,
                "max_output_tokens": max_tokens,
                **({"response_mime_type": "application/json"} if json_mode else {}),
            },
        )
        user_turns = [
            {"role": "user" if m.role == Role.USER else "model", "parts": [m.content]}
            for m in messages
            if m.role != Role.SYSTEM
        ]
        t0 = time.perf_counter()
        resp = await model.generate_content_async(user_turns)
        latency = time.perf_counter() - t0
        text = getattr(resp, "text", "") or ""
        # Gemini doesn't always return token counts; estimate.
        prompt = "\n".join(m.content for m in messages)
        usage = LLMUsage(
            prompt_tokens=count_tokens_estimate(prompt),
            completion_tokens=count_tokens_estimate(text),
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
