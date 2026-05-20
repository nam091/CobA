"""Ollama provider — local LLM (Qwen2.5-Coder, Llama 3.1, DeepSeek-Coder, ...)."""

from __future__ import annotations

import time

import httpx

from coba.llm.base import LLMProvider, ProviderUnavailable
from coba.utils.logging import get_logger
from coba.utils.sanitize import count_tokens_estimate
from coba.utils.schemas import LLMMessage, LLMResponse, LLMUsage

log = get_logger("coba.llm.ollama")


class OllamaProvider(LLMProvider):
    """Local LLM via the Ollama HTTP API.

    Supports any model installed in Ollama (`ollama pull qwen2.5-coder:7b`).
    """

    name = "ollama"

    def __init__(self, base_url: str = "http://localhost:11434") -> None:
        self.base_url = base_url.rstrip("/")

    def available(self) -> bool:
        try:
            with httpx.Client(timeout=2.0) as client:
                r = client.get(f"{self.base_url}/api/tags")
                return r.status_code == 200
        except Exception:
            return False

    def supports(self, model_id: str) -> bool:
        # Ollama model ids commonly contain a colon (size/tag).
        return ":" in model_id or any(
            model_id.startswith(p) for p in ("qwen", "llama", "deepseek", "codellama", "mistral")
        )

    async def complete(
        self,
        model_id: str,
        messages: list[LLMMessage],
        *,
        temperature: float = 0.0,
        max_tokens: int = 1024,
        json_mode: bool = False,
    ) -> LLMResponse:
        payload = {
            "model": model_id,
            "messages": [{"role": m.role.value, "content": m.content} for m in messages],
            "options": {
                "temperature": temperature,
                "num_predict": max_tokens,
            },
            "stream": False,
        }
        if json_mode:
            payload["format"] = "json"

        t0 = time.perf_counter()
        async with httpx.AsyncClient(timeout=180.0) as client:
            try:
                r = await client.post(f"{self.base_url}/api/chat", json=payload)
            except httpx.RequestError as exc:
                raise ProviderUnavailable(f"Ollama unreachable: {exc}") from exc
        latency = time.perf_counter() - t0

        if r.status_code != 200:
            raise ProviderUnavailable(f"Ollama HTTP {r.status_code}: {r.text}")

        data = r.json()
        text = data.get("message", {}).get("content", "")
        # Ollama returns eval_count / prompt_eval_count.
        prompt_tokens = int(data.get("prompt_eval_count") or count_tokens_estimate(str(payload)))
        completion_tokens = int(data.get("eval_count") or count_tokens_estimate(text))
        usage = LLMUsage(prompt_tokens=prompt_tokens, completion_tokens=completion_tokens)
        return LLMResponse(
            text=text,
            model=model_id,
            provider=self.name,
            usage=usage,
            cost_usd=0.0,
            latency_seconds=latency,
        )
