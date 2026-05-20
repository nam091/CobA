"""Core data models used across CobA components.

All inter-component IO goes through pydantic schemas so we get validation
for free and a single source of truth for the CLI / API / file formats.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from enum import Enum

from pydantic import BaseModel, Field, field_validator


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------
class Severity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @classmethod
    def from_str(cls, value: str | None) -> Severity:
        if not value:
            return cls.MEDIUM
        v = value.strip().lower()
        for member in cls:
            if member.value == v:
                return member
        # heuristics for tool outputs
        if v in ("info", "informational", "note"):
            return cls.LOW
        if v in ("error", "warning"):
            return cls.MEDIUM
        return cls.MEDIUM


class Verdict(str, Enum):
    TRUE_POSITIVE = "TRUE_POSITIVE"
    FALSE_POSITIVE = "FALSE_POSITIVE"
    UNVERIFIED = "UNVERIFIED"


class Language(str, Enum):
    PYTHON = "python"
    JAVA = "java"
    C = "c"
    CPP = "cpp"
    JAVASCRIPT = "javascript"
    TYPESCRIPT = "typescript"
    UNKNOWN = "unknown"

    @classmethod
    def from_path(cls, path: str) -> Language:
        path = path.lower()
        if path.endswith(".py"):
            return cls.PYTHON
        if path.endswith(".java"):
            return cls.JAVA
        if path.endswith((".c", ".h")):
            return cls.C
        if path.endswith((".cc", ".cpp", ".cxx", ".hpp", ".hxx")):
            return cls.CPP
        if path.endswith((".js", ".mjs", ".cjs", ".jsx")):
            return cls.JAVASCRIPT
        if path.endswith((".ts", ".tsx")):
            return cls.TYPESCRIPT
        return cls.UNKNOWN


# ---------------------------------------------------------------------------
# Chunk
# ---------------------------------------------------------------------------
class Chunk(BaseModel):
    """A logical unit of source code passed to the LLM."""

    chunk_id: str = Field(default_factory=lambda: uuid.uuid4().hex)
    file: str
    language: Language
    function: str | None = None
    line_start: int
    line_end: int
    body: str
    imports: list[str] = Field(default_factory=list)
    callers: list[str] = Field(default_factory=list)
    callees: list[str] = Field(default_factory=list)
    static_hints: list[StaticHint] = Field(default_factory=list)

    @field_validator("body")
    @classmethod
    def _strip(cls, v: str) -> str:
        return v.rstrip()


class StaticHint(BaseModel):
    """Output of a SAST tool, normalized."""

    tool: str
    rule_id: str
    line: int
    message: str
    cwe: str | None = None
    severity: Severity = Severity.MEDIUM


# ---------------------------------------------------------------------------
# Findings
# ---------------------------------------------------------------------------
class RawFinding(BaseModel):
    """LLM Detector output (before verification)."""

    cwe: str
    severity: Severity
    confidence: float = Field(ge=0.0, le=1.0)
    line_start: int
    line_end: int
    title: str
    description: str
    data_flow: list[str] = Field(default_factory=list)
    fix_suggestion: str | None = None

    @field_validator("cwe")
    @classmethod
    def _normalize_cwe(cls, v: str) -> str:
        v = v.strip().upper()
        if not v.startswith("CWE-"):
            v = f"CWE-{v}"
        return v


class Finding(BaseModel):
    """Final finding emitted by CobA pipeline."""

    id: str = Field(default_factory=lambda: uuid.uuid4().hex)
    file: str
    function: str | None = None
    line_start: int
    line_end: int
    cwe: str
    severity: Severity
    confidence: float = Field(ge=0.0, le=1.0)
    title: str
    description: str
    data_flow: list[str] = Field(default_factory=list)
    fix_suggestion: str | None = None
    sources: list[str] = Field(default_factory=list)  # ["semgrep:rule_id", "llm-detector"]
    verifier_verdict: Verdict = Verdict.UNVERIFIED
    verifier_rationale: str | None = None
    cost_usd: float = 0.0
    timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))


# ---------------------------------------------------------------------------
# Scan request / response
# ---------------------------------------------------------------------------
class ScanRequest(BaseModel):
    target_path: str | None = None
    git_url: str | None = None
    languages: list[Language] | None = None  # None => auto-detect all
    profile: str = "fast"  # "fast" | "accuracy"
    no_cloud: bool = False  # privacy mode


class ScanReport(BaseModel):
    scan_id: str = Field(default_factory=lambda: uuid.uuid4().hex)
    target: str
    started_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    finished_at: datetime | None = None
    duration_seconds: float | None = None
    findings: list[Finding] = Field(default_factory=list)
    stats: ScanStats | None = None


class ScanStats(BaseModel):
    n_files: int = 0
    n_chunks: int = 0
    n_static_findings: int = 0
    n_raw_findings: int = 0
    n_final_findings: int = 0
    n_verifier_rejected: int = 0
    n_schema_rejected: int = 0
    total_cost_usd: float = 0.0
    timings: dict[str, float] = Field(default_factory=dict)


# ---------------------------------------------------------------------------
# LLM messages
# ---------------------------------------------------------------------------
class Role(str, Enum):
    SYSTEM = "system"
    USER = "user"
    ASSISTANT = "assistant"


class LLMMessage(BaseModel):
    role: Role
    content: str


class LLMUsage(BaseModel):
    prompt_tokens: int = 0
    completion_tokens: int = 0


class LLMResponse(BaseModel):
    text: str
    model: str
    provider: str
    usage: LLMUsage = Field(default_factory=LLMUsage)
    cost_usd: float = 0.0
    latency_seconds: float = 0.0


# Forward-ref resolution: pydantic needs to know about types defined later
Chunk.model_rebuild()
ScanReport.model_rebuild()
