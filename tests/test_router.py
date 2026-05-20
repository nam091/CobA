"""Unit tests for ``coba.llm.router`` (offline / mock only)."""

from coba.config.settings import Settings
from coba.llm.base import TaskKind
from coba.llm.router import LLMRouter, RoutePolicy


def test_policy_has_routes_for_known_tasks() -> None:
    settings = Settings(
        openai_api_key=None,
        anthropic_api_key=None,
        google_api_key=None,
    )
    p = RoutePolicy.from_settings(settings)
    assert p.candidates(TaskKind.DETECTOR), "Detector route must have candidates"
    assert p.candidates(TaskKind.VERIFIER), "Verifier route must have candidates"


def test_router_initializes_without_keys() -> None:
    settings = Settings(
        openai_api_key=None,
        anthropic_api_key=None,
        google_api_key=None,
    )
    r = LLMRouter(settings)
    assert r.policy is not None
    assert r.cost.spent == 0.0
