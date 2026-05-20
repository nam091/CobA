"""Unit test: Orchestrator._run_detector honours coba_scan_budget_usd."""

from __future__ import annotations

import asyncio
from types import SimpleNamespace
from typing import Any

import pytest

from coba.agent.loop import Orchestrator
from coba.utils.schemas import Chunk, Language, RawFinding, Severity


def _chunk(file: str = "a.py", start: int = 1, end: int = 10) -> Chunk:
    return Chunk(
        file=file,
        language=Language.PYTHON,
        function="f",
        line_start=start,
        line_end=end,
        body="...",
    )


class _StubDetector:
    """Detector double that bills exactly $0.30 per call."""

    def __init__(self, router: Any) -> None:
        self.router = router
        self.calls = 0

    async def detect(self, chunk: Chunk, hints: list[Any]) -> list[RawFinding]:
        self.calls += 1
        self.router.cost._spent += 0.30  # simulate LLM bill
        return [
            RawFinding(
                cwe="CWE-89",
                line_start=chunk.line_start,
                line_end=chunk.line_end,
                severity=Severity.MEDIUM,
                confidence=0.7,
                title="t",
                description="d",
                data_flow=[],
                fix_suggestion="fix",
            )
        ]


class _Cost:
    """Minimal CostTracker stand-in with the ``.spent`` property."""

    def __init__(self) -> None:
        self._spent = 0.0

    @property
    def spent(self) -> float:
        return self._spent


def _orch_with_budget(budget: float, parallel: int = 1) -> Orchestrator:
    orch = Orchestrator.__new__(Orchestrator)
    orch.settings = SimpleNamespace(
        coba_scan_budget_usd=budget,
        coba_parallel_llm_calls=parallel,
    )
    orch.router = SimpleNamespace(cost=_Cost())
    orch.detector = _StubDetector(orch.router)
    return orch


def test_budget_zero_means_no_cap() -> None:
    orch = _orch_with_budget(budget=0.0)
    chunks = [_chunk(f"f{i}.py") for i in range(5)]
    pairs, skipped = asyncio.run(orch._run_detector(chunks, {}))
    assert len(pairs) == 5
    assert skipped == 0


def test_budget_cap_stops_after_threshold() -> None:
    # $1 budget, $0.30/call → expect 4 calls (spent jumps to $1.20 on 4th).
    orch = _orch_with_budget(budget=1.0)
    chunks = [_chunk(f"f{i}.py") for i in range(10)]
    pairs, skipped = asyncio.run(orch._run_detector(chunks, {}))
    # The check is `spent >= budget` *before* the call → we keep running
    # while spent < 1.0; after the 4th call spent = 1.2 → skip remaining 6.
    assert len(pairs) == 4
    assert skipped == 6


def test_budget_cap_skips_everything_when_already_over() -> None:
    orch = _orch_with_budget(budget=0.10)
    orch.router.cost._spent = 5.0  # already blown past budget
    chunks = [_chunk("f.py") for _ in range(3)]
    pairs, skipped = asyncio.run(orch._run_detector(chunks, {}))
    assert pairs == []
    assert skipped == 3


@pytest.mark.parametrize("budget", [0.0, 0.5, 100.0])
def test_budget_returns_correct_pair_count_for_each_call(budget: float) -> None:
    orch = _orch_with_budget(budget=budget)
    chunks = [_chunk("a.py") for _ in range(2)]
    pairs, _ = asyncio.run(orch._run_detector(chunks, {}))
    for ch, raws in pairs:
        assert raws  # each call produced at least one RawFinding
        assert ch.file == "a.py"
