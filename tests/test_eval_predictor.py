"""Unit tests for :class:`coba.eval.predictor.OrchestratorPredictor`."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest

from coba.eval.predictor import OrchestratorPredictor
from coba.eval.runner import run_eval
from coba.eval.schemas import EvalConfig, GroundTruth
from coba.utils.schemas import (
    Finding,
    ScanReport,
    ScanRequest,
    ScanStats,
    Severity,
    Verdict,
)


class _StubOrchestrator:
    """Fake orchestrator that returns a canned :class:`ScanReport`."""

    def __init__(self, findings_by_file: dict[str, list[Finding]]):
        self._findings_by_file = findings_by_file
        self.calls: list[ScanRequest] = []

    async def scan(self, request: ScanRequest) -> ScanReport:
        self.calls.append(request)
        target = request.target_path or ""
        # Look up by basename to keep the test independent of where
        # the dataset sits on disk.
        basename = Path(target).name
        findings = next(
            (v for k, v in self._findings_by_file.items() if Path(k).name == basename),
            [],
        )
        return ScanReport(
            target=target,
            started_at=datetime.now(UTC),
            finished_at=datetime.now(UTC),
            duration_seconds=0.01,
            findings=findings,
            stats=ScanStats(total_cost_usd=0.001),
        )


def _make_finding(file: str, line: int, cwe: str, confidence: float = 0.9) -> Finding:
    return Finding(
        file=file,
        line_start=line,
        line_end=line,
        cwe=cwe,
        severity=Severity.HIGH,
        confidence=confidence,
        title="t",
        description="d",
        verifier_verdict=Verdict.TRUE_POSITIVE,
    )


@pytest.mark.asyncio
async def test_predictor_emits_predictions_per_finding(tmp_path: Path) -> None:
    """A finding at the GT line yields a TP-shaped prediction."""
    sample_dir = tmp_path / "primevul" / "samples"
    sample_dir.mkdir(parents=True)
    sample_file = sample_dir / "s001.c"
    sample_file.write_text("// vulnerable C file\n", encoding="utf-8")

    gts = [
        GroundTruth(
            sample_id="s001",
            file="primevul/samples/s001.c",
            line_start=10,
            line_end=12,
            cwe="CWE-89",
            vulnerable=True,
        )
    ]
    orch = _StubOrchestrator({"s001.c": [_make_finding(str(sample_file), 11, "CWE-89")]})
    predictor = OrchestratorPredictor(orch, dataset_root=tmp_path)

    preds = await predictor(gts)

    assert len(preds) == 1
    p = preds[0]
    # Sample_id flows through so the matcher can attribute the prediction.
    assert p.sample_id == "s001"
    # File path is normalised back to the dataset-relative form (not the
    # absolute scan path) so the matcher's _norm_path can compare.
    assert p.file == "primevul/samples/s001.c"
    assert p.cwe == "CWE-89"
    assert p.line_start == 11
    # Confirm Orchestrator received a ScanRequest pointing at the right file.
    assert len(orch.calls) == 1
    assert orch.calls[0].target_path is not None
    assert orch.calls[0].target_path.endswith("s001.c")


@pytest.mark.asyncio
async def test_predictor_caches_scans_per_file(tmp_path: Path) -> None:
    """Two GT samples pointing at the same file must trigger one scan."""
    sample_dir = tmp_path / "primevul" / "samples"
    sample_dir.mkdir(parents=True)
    sample_file = sample_dir / "shared.c"
    sample_file.write_text("// shared\n", encoding="utf-8")

    gts = [
        GroundTruth(
            sample_id=f"sid{i}",
            file="primevul/samples/shared.c",
            line_start=10 + i,
            line_end=10 + i,
            cwe="CWE-79",
        )
        for i in range(3)
    ]
    orch = _StubOrchestrator({"shared.c": [_make_finding(str(sample_file), 11, "CWE-79")]})
    predictor = OrchestratorPredictor(orch, dataset_root=tmp_path)

    preds = await predictor(gts)

    # One scan, but three predictions (one attributed to each sample_id).
    assert len(orch.calls) == 1
    assert len(preds) == 3
    assert {p.sample_id for p in preds} == {"sid0", "sid1", "sid2"}


@pytest.mark.asyncio
async def test_predictor_skips_missing_files(tmp_path: Path) -> None:
    """Samples whose file is not on disk are logged and dropped silently."""
    gts = [
        GroundTruth(
            sample_id="missing",
            file="does/not/exist.c",
            line_start=1,
            line_end=1,
            cwe="CWE-22",
        )
    ]
    orch = _StubOrchestrator({})
    predictor = OrchestratorPredictor(orch, dataset_root=tmp_path)

    preds = await predictor(gts)

    assert preds == []
    assert orch.calls == []


@pytest.mark.asyncio
async def test_predictor_runner_end_to_end_matches_correctly(tmp_path: Path) -> None:
    """End-to-end: predictor + runner produce a perfect-score EvalRun."""
    # Two positive samples, one negative.
    sample_dir = tmp_path / "primevul" / "samples"
    sample_dir.mkdir(parents=True)
    (sample_dir / "vuln_a.c").write_text("// a\n", encoding="utf-8")
    (sample_dir / "vuln_b.c").write_text("// b\n", encoding="utf-8")
    (sample_dir / "clean_c.c").write_text("// c\n", encoding="utf-8")
    labels_path = tmp_path / "primevul" / "labels.jsonl"
    labels_path.write_text(
        '{"sample_id":"a","file":"primevul/samples/vuln_a.c",'
        '"line_start":10,"line_end":10,"cwe":"CWE-89"}\n'
        '{"sample_id":"b","file":"primevul/samples/vuln_b.c",'
        '"line_start":20,"line_end":20,"cwe":"CWE-79"}\n'
        '{"sample_id":"c","file":"primevul/samples/clean_c.c",'
        '"line_start":0,"line_end":0,"vulnerable":false}\n',
        encoding="utf-8",
    )

    orch = _StubOrchestrator(
        {
            "vuln_a.c": [_make_finding(str(sample_dir / "vuln_a.c"), 10, "CWE-89")],
            "vuln_b.c": [_make_finding(str(sample_dir / "vuln_b.c"), 20, "CWE-79")],
            # clean_c.c → no findings (correct TN)
        }
    )
    predictor = OrchestratorPredictor(orch, dataset_root=tmp_path)

    cfg = EvalConfig(name="t", dataset="primevul", subset=10, line_tolerance=2)
    run = await run_eval(cfg, predictor, dataset_root=tmp_path)

    assert run.n_samples == 3
    assert run.n_predictions == 2
    assert run.metrics["precision"] == 1.0
    assert run.metrics["recall"] == 1.0
    assert run.metrics["fp_rate"] == 0.0
