"""Application settings loaded from environment variables / .env."""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Central settings object — loaded once and injected everywhere.

    See `.env.example` for the full list of variables.
    """

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # --- LLM API keys (optional; provider auto-disables if missing) ----------
    openai_api_key: str | None = None
    anthropic_api_key: str | None = None
    google_api_key: str | None = None

    # --- LLM custom endpoints (OpenAI / Anthropic compatible APIs) ----------
    # When set, the corresponding provider routes through the custom base URL
    # instead of the vendor's default. This unlocks OpenAI-compatible gateways
    # such as OpenRouter, Together, Groq, vLLM, LiteLLM, DeepSeek, Mistral, or
    # an Ollama instance exposing the `/v1/chat/completions` endpoint. The
    # provider also relaxes its `supports()` check so arbitrary model ids
    # (e.g. ``meta-llama/Llama-3.1-8B-Instruct``) can be routed.
    openai_base_url: str | None = None
    anthropic_base_url: str | None = None

    # --- Ollama (local, native /api/chat protocol) ---------------------------
    ollama_base_url: str = "http://localhost:11434"
    ollama_default_model: str = "qwen2.5-coder:7b"

    # --- LLM routing policy --------------------------------------------------
    coba_llm_detector: str = Field(default="gpt-4o-mini", alias="COBA_LLM_DETECTOR")
    coba_llm_verifier: str = Field(default="claude-3-5-sonnet-20241022", alias="COBA_LLM_VERIFIER")
    coba_llm_offline_fallback: str = Field(
        default="qwen2.5-coder:7b", alias="COBA_LLM_OFFLINE_FALLBACK"
    )
    coba_llm_daily_budget_usd: float = Field(default=5.0, alias="COBA_LLM_DAILY_BUDGET_USD")
    coba_scan_budget_usd: float = Field(default=2.0, alias="COBA_SCAN_BUDGET_USD")
    """Per-scan hard cap on LLM spend (USD). 0 disables the check."""

    # --- Tool binaries -------------------------------------------------------
    semgrep_bin: str = "semgrep"
    joern_bin: str = "joern"
    joern_parse_bin: str = "joern-parse"
    bandit_bin: str = "bandit"
    gitleaks_bin: str = "gitleaks"

    # --- API server ----------------------------------------------------------
    coba_host: str = "0.0.0.0"
    coba_port: int = 8000
    coba_log_level: str = "INFO"

    # --- RAG -----------------------------------------------------------------
    chroma_persist_dir: Path = Path(".coba_data/chroma")
    embedding_model: str = "sentence-transformers/all-MiniLM-L6-v2"

    # --- Limits --------------------------------------------------------------
    coba_max_file_size_kb: int = 512
    coba_max_chunk_tokens: int = 2000
    coba_parallel_llm_calls: int = 4
    coba_skip_cache_enabled: bool = Field(default=True, alias="COBA_SKIP_CACHE_ENABLED")

    # --- Profile -------------------------------------------------------------
    coba_profile: str = "fast"  # "fast" or "accuracy"

    # --- Privacy -------------------------------------------------------------
    coba_no_cloud: bool = False  # if True, only use local LLM

    # ---- Helpers ------------------------------------------------------------
    @property
    def cache_dir(self) -> Path:
        return Path(".coba_cache")

    @property
    def data_dir(self) -> Path:
        return Path(".coba_data")

    def ensure_dirs(self) -> None:
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.chroma_persist_dir.mkdir(parents=True, exist_ok=True)


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Return a cached singleton ``Settings`` instance."""
    settings = Settings()
    settings.ensure_dirs()
    return settings
