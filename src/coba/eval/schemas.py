"""Pydantic schemas for the evaluation framework."""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field, field_validator

from coba.utils.schemas import Severity


class GroundTruth(BaseModel):
    """A single ground-truth vulnerability label from a benchmark dataset.

    A *negative* sample (vulnerable=False) carries ``cwe=None`` and is used
    to score false-positive rate. PrimeVul, OWASP Benchmark and Juliet all
    encode samples this way after their respective loaders normalize them.
    """

    sample_id: str
    file: str
    line_start: int = Field(ge=0)
    line_end: int = Field(ge=0)
    cwe: str | None = None
    vulnerable: bool = True
    dataset: str = ""
    language: str = ""
    severity: Severity | None = None

    @field_validator("cwe")
    @classmethod
    def _normalize_cwe(cls, v: str | None) -> str | None:
        if v is None:
            return None
        v = v.strip().upper()
        if v.startswith("CWE-"):
            return v
        return f"CWE-{v.lstrip('CWE-')}" if v else None


class Prediction(BaseModel):
    """A finding emitted by a detector under test (CobA or a baseline)."""

    sample_id: str
    file: str
    line_start: int = Field(ge=0)
    line_end: int = Field(ge=0)
    cwe: str
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    detector: str = "coba"

    @field_validator("cwe")
    @classmethod
    def _normalize_cwe(cls, v: str) -> str:
        v = v.strip().upper()
        if not v.startswith("CWE-"):
            v = f"CWE-{v}"
        return v


class EvalConfig(BaseModel):
    """Top-level configuration for a single eval run."""

    model_config = ConfigDict(extra="forbid")

    name: str = "coba-default"
    dataset: str = "primevul"
    subset: int = Field(default=100, ge=1)
    detector_profile: str = "fast"
    seed: int = 42
    line_tolerance: int = Field(default=5, ge=0)
    require_cwe_match: bool = True
    predictor: str = Field(
        default="zero",
        description=(
            "Which predictor to use: 'zero' (no-op, default) emits an empty "
            "finding list; 'orchestrator' wires `coba.agent.loop.Orchestrator`"
            " through `OrchestratorPredictor` and produces real predictions."
        ),
    )
    no_cloud: bool = False


class EvalRun(BaseModel):
    """One row in the leaderboard: a (config x dataset) combination."""

    config: EvalConfig
    started_at: datetime
    finished_at: datetime | None = None
    n_samples: int = 0
    n_predictions: int = 0
    metrics: dict[str, float] = Field(default_factory=dict)
    cost_usd: float = 0.0


class EvalReport(BaseModel):
    """Aggregate of multiple runs (e.g. CobA-fast vs Semgrep vs LLM-only)."""

    runs: list[EvalRun] = Field(default_factory=list)
    generated_at: datetime
