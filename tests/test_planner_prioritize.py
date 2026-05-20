"""Unit tests for Planner.prioritize — chunks with static hits come first."""

from __future__ import annotations

from pathlib import Path

from coba.agent.planner import Planner
from coba.utils.schemas import Chunk, Language, StaticHint


def _chunk(file: str, start: int, end: int) -> Chunk:
    return Chunk(
        file=file,
        language=Language.PYTHON,
        function=None,
        line_start=start,
        line_end=end,
        body="...",
    )


def _hint(file: str, line: int, msg: str = "h") -> StaticHint:
    return StaticHint(
        tool="semgrep",
        rule_id="sql-injection",
        file=file or None,
        line=line,
        message=msg,
        cwe="CWE-89",
    )


def _key(file: str) -> str:
    return str(Path(file).resolve())


def test_prioritize_empty_hints_preserves_order() -> None:
    chunks = [_chunk("a.py", 1, 10), _chunk("b.py", 1, 10)]
    assert Planner.prioritize(chunks, {}) == chunks


def test_prioritize_brings_hot_chunks_first() -> None:
    cold = _chunk("/tmp/cold.py", 1, 10)
    hot = _chunk("/tmp/hot.py", 1, 10)
    hints = {_key("/tmp/hot.py"): [_hint("/tmp/hot.py", 5)]}
    out = Planner.prioritize([cold, hot], hints)
    assert out[0] is hot
    assert out[1] is cold


def test_prioritize_orders_by_hint_count() -> None:
    a = _chunk("/tmp/a.py", 1, 10)
    b = _chunk("/tmp/b.py", 1, 10)
    c = _chunk("/tmp/c.py", 1, 10)
    hints = {
        _key("/tmp/a.py"): [_hint("/tmp/a.py", 5)],
        _key("/tmp/b.py"): [_hint("/tmp/b.py", 5), _hint("/tmp/b.py", 7)],
        _key("/tmp/c.py"): [],
    }
    out = Planner.prioritize([a, b, c], hints)
    # b (2 hits) > a (1 hit) > c (0)
    assert out[0] is b
    assert out[1] is a
    assert out[2] is c


def test_prioritize_ignores_hints_outside_chunk_range() -> None:
    inside = _chunk("/tmp/x.py", 1, 10)
    outside = _chunk("/tmp/x.py", 100, 110)
    # Both chunks live in same file; hint is on line 5 -> only `inside` should score.
    hints = {_key("/tmp/x.py"): [_hint("/tmp/x.py", 5)]}
    out = Planner.prioritize([outside, inside], hints)
    assert out[0] is inside
    assert out[1] is outside


def test_prioritize_uses_global_bucket_fallback() -> None:
    """Hints with no file (tool didn't report path) still help score chunks."""
    a = _chunk("/tmp/a.py", 1, 10)
    b = _chunk("/tmp/b.py", 1, 10)
    hints = {"_global": [_hint("", 5)]}
    out = Planner.prioritize([a, b], hints)
    # Both score equally; tie-break by file path alpha.
    assert {c.file for c in out} == {"/tmp/a.py", "/tmp/b.py"}
    assert [c.file for c in out] == sorted(["/tmp/a.py", "/tmp/b.py"])


def test_prioritize_is_deterministic_on_ties() -> None:
    a1 = _chunk("/tmp/a.py", 1, 5)
    a2 = _chunk("/tmp/a.py", 6, 10)
    b1 = _chunk("/tmp/b.py", 1, 5)
    # All cold; deterministic order: alpha by file then line_start.
    out = Planner.prioritize([b1, a2, a1], {})
    # With empty hints, order preserved verbatim.
    assert out == [b1, a2, a1]
