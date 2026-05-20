"""Unit tests for ``coba.utils.schemas``."""

from coba.utils.schemas import (
    Chunk,
    Finding,
    Language,
    RawFinding,
    Severity,
    StaticHint,
    Verdict,
)


def test_language_from_path() -> None:
    assert Language.from_path("a.py") == Language.PYTHON
    assert Language.from_path("a.java") == Language.JAVA
    assert Language.from_path("a.c") == Language.C
    assert Language.from_path("a.cpp") == Language.CPP
    assert Language.from_path("a.js") == Language.JAVASCRIPT
    assert Language.from_path("a.ts") == Language.TYPESCRIPT
    assert Language.from_path("a.unknown") == Language.UNKNOWN


def test_severity_from_str() -> None:
    assert Severity.from_str("HIGH") == Severity.HIGH
    assert Severity.from_str("info") == Severity.LOW
    assert Severity.from_str(None) == Severity.MEDIUM
    assert Severity.from_str("random-garbage") == Severity.MEDIUM


def test_raw_finding_cwe_normalization() -> None:
    rf = RawFinding(
        cwe="89",
        severity=Severity.HIGH,
        confidence=0.9,
        line_start=10,
        line_end=12,
        title="SQLi",
        description="injection",
    )
    assert rf.cwe == "CWE-89"


def test_chunk_strips_trailing_whitespace() -> None:
    c = Chunk(
        file="x.py",
        language=Language.PYTHON,
        line_start=1,
        line_end=2,
        body="def f():\n  pass\n   \n",
    )
    assert c.body.endswith("pass")


def test_finding_default_unverified() -> None:
    f = Finding(
        file="x.py",
        line_start=1,
        line_end=1,
        cwe="CWE-89",
        severity=Severity.HIGH,
        confidence=0.5,
        title="t",
        description="d",
    )
    assert f.verifier_verdict == Verdict.UNVERIFIED
    assert isinstance(f.id, str) and len(f.id) >= 8


def test_static_hint_defaults() -> None:
    h = StaticHint(tool="semgrep", rule_id="r1", line=10, message="m")
    assert h.severity == Severity.MEDIUM
    assert h.cwe is None
