"""Tests for OpenAI/Anthropic-compatible custom base URL support.

These tests intercept the AsyncOpenAI / AsyncAnthropic constructor
arguments to verify the provider passes ``base_url`` through correctly,
and check ``supports()`` / ``available()`` semantics for custom endpoints.

No real network traffic happens \u2014 we only inspect what the provider
would have sent to the SDK client.
"""

from __future__ import annotations

from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from coba.config.settings import Settings
from coba.llm.anthropic_provider import AnthropicProvider
from coba.llm.base import ProviderUnavailable
from coba.llm.openai_provider import OpenAIProvider
from coba.llm.router import LLMRouter


def test_openai_supports_only_gpt_when_no_base_url() -> None:
    p = OpenAIProvider("sk-real")
    assert p.supports("gpt-4o-mini") is True
    assert p.supports("qwen2.5-coder") is False
    assert p.supports("meta-llama/Llama-3.1-8B-Instruct") is False
    # Other-vendor namespaces always rejected
    assert p.supports("claude-3-5-haiku-20241022") is False
    assert p.supports("gemini-1.5-flash") is False


def test_openai_supports_arbitrary_models_when_base_url_set() -> None:
    p = OpenAIProvider("sk-real", base_url="https://router.example.com/v1")
    assert p.supports("gpt-4o-mini") is True
    # Custom endpoint accepts anything that isn't another vendor's namespace.
    assert p.supports("qwen2.5-coder") is True
    assert p.supports("deepseek-coder") is True
    assert p.supports("meta-llama/Llama-3.1-8B-Instruct") is True
    # But still rejects other vendors so the router can dispatch correctly.
    assert p.supports("claude-3-5-haiku-20241022") is False
    assert p.supports("gemini-1.5-flash") is False


def test_openai_available_relaxed_when_base_url_set() -> None:
    # No API key + no base URL → not available (vanilla OpenAI requires a key).
    assert OpenAIProvider(api_key=None).available() is False
    # No API key + custom base URL → available (private endpoints don't need a key).
    assert OpenAIProvider(api_key=None, base_url="http://localhost:11434/v1").available() is True
    # Vanilla key-based case is unaffected.
    assert OpenAIProvider(api_key="sk-real").available() is True


def test_openai_get_client_passes_base_url_to_sdk() -> None:
    """`AsyncOpenAI` must be constructed with the custom ``base_url``."""
    fake_async_openai = MagicMock(name="AsyncOpenAI")
    fake_async_openai.return_value = MagicMock(name="client")

    with patch.dict(
        "sys.modules",
        {"openai": MagicMock(AsyncOpenAI=fake_async_openai)},
    ):
        p = OpenAIProvider("sk-key", base_url="https://router.example.com/v1")
        p._get_client()  # type: ignore[reportPrivateUsage]

    fake_async_openai.assert_called_once()
    _, kwargs = fake_async_openai.call_args
    assert kwargs["api_key"] == "sk-key"
    assert kwargs["base_url"] == "https://router.example.com/v1"


def test_openai_get_client_omits_base_url_when_not_set() -> None:
    """Vanilla OpenAI calls must not pass a ``base_url`` kwarg."""
    fake_async_openai = MagicMock(name="AsyncOpenAI")
    fake_async_openai.return_value = MagicMock(name="client")

    with patch.dict(
        "sys.modules",
        {"openai": MagicMock(AsyncOpenAI=fake_async_openai)},
    ):
        p = OpenAIProvider("sk-key")
        p._get_client()  # type: ignore[reportPrivateUsage]

    _, kwargs = fake_async_openai.call_args
    assert "base_url" not in kwargs
    assert kwargs["api_key"] == "sk-key"


def test_openai_get_client_supplies_placeholder_key_for_keyless_endpoint() -> None:
    """Private endpoints with no key still get a non-empty placeholder."""
    fake_async_openai = MagicMock(name="AsyncOpenAI")
    fake_async_openai.return_value = MagicMock(name="client")

    with patch.dict(
        "sys.modules",
        {"openai": MagicMock(AsyncOpenAI=fake_async_openai)},
    ):
        p = OpenAIProvider(api_key=None, base_url="http://localhost:11434/v1")
        p._get_client()  # type: ignore[reportPrivateUsage]

    _, kwargs = fake_async_openai.call_args
    assert kwargs["base_url"] == "http://localhost:11434/v1"
    assert kwargs["api_key"]  # non-empty placeholder


def test_openai_get_client_raises_without_key_and_url() -> None:
    p = OpenAIProvider(api_key=None)
    with pytest.raises(ProviderUnavailable, match="OPENAI_API_KEY"):
        p._get_client()  # type: ignore[reportPrivateUsage]


def test_anthropic_get_client_passes_base_url_to_sdk() -> None:
    fake_async_anthropic = MagicMock(name="AsyncAnthropic")
    fake_async_anthropic.return_value = MagicMock(name="client")

    with patch.dict(
        "sys.modules",
        {"anthropic": MagicMock(AsyncAnthropic=fake_async_anthropic)},
    ):
        p = AnthropicProvider("sk-claude", base_url="https://relay.example.com")
        p._get_client()  # type: ignore[reportPrivateUsage]

    fake_async_anthropic.assert_called_once()
    _, kwargs = fake_async_anthropic.call_args
    assert kwargs["api_key"] == "sk-claude"
    assert kwargs["base_url"] == "https://relay.example.com"


def test_anthropic_get_client_omits_base_url_when_not_set() -> None:
    fake_async_anthropic = MagicMock(name="AsyncAnthropic")
    fake_async_anthropic.return_value = MagicMock(name="client")

    with patch.dict(
        "sys.modules",
        {"anthropic": MagicMock(AsyncAnthropic=fake_async_anthropic)},
    ):
        p = AnthropicProvider("sk-claude")
        p._get_client()  # type: ignore[reportPrivateUsage]

    _, kwargs = fake_async_anthropic.call_args
    assert "base_url" not in kwargs


def test_router_forwards_settings_base_urls_to_providers() -> None:
    settings = Settings(
        openai_api_key="sk-key",
        anthropic_api_key="sk-claude",
        google_api_key=None,
        openai_base_url="https://router.example.com/v1",
        anthropic_base_url="https://anthropic.relay.example.com",
    )
    router = LLMRouter(settings)

    providers_by_name: dict[str, Any] = {p.name: p for p in router._providers}
    assert providers_by_name["openai"].base_url == "https://router.example.com/v1"
    assert providers_by_name["anthropic"].base_url == "https://anthropic.relay.example.com"


def test_router_resolves_custom_model_id_through_openai_when_base_url_set() -> None:
    """A non-gpt model id must route through OpenAIProvider once base_url is set."""
    settings = Settings(
        openai_api_key=None,
        anthropic_api_key=None,
        google_api_key=None,
        openai_base_url="http://localhost:8000/v1",
    )
    router = LLMRouter(settings)

    provider = router._resolve("meta-llama/Llama-3.1-8B-Instruct")
    assert provider is not None
    assert provider.name == "openai"
