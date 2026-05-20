"""Integration tests for the eval runner + dataset loader + report writer."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from coba.eval.cli import run_cli
from coba.eval.datasets import load_jsonl_dataset, load_primevul
from coba.eval.report import assemble_report, write_all
from coba.eval.runner import run_eval
from coba.eval.schemas import EvalConfig, GroundTruth, Prediction


def _write_jsonl(path: Path, rows: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        for r in rows:
            f.write(json.dumps(r) + "\n")


def test_load_jsonl_dataset_skips_comments(tmp_path: Path) -> None:
    p = tmp_path / "labels.jsonl"
    p.write_text(
        "// This is a comment\n"
        '{"sample_id":"s1","file":"a.py","line_start":1,"line_end":2,"cwe":"CWE-89"}\n'
        "\n"  # blank
        '{"sample_id":"s2","file":"b.py","line_start":3,"line_end":4,"vulnerable":false}\n',
        encoding="utf-8",
    )
    rows = load_jsonl_dataset(p, "test")
    assert len(rows) == 2
    assert rows[0].sample_id == "s1"
    assert rows[1].vulnerable is False


def test_load_primevul_subset_truncates(tmp_path: Path) -> None:
    rows = [
        {"sample_id": f"s{i}", "file": "a.py", "line_start": i, "line_end": i} for i in range(10)
    ]
    _write_jsonl(tmp_path / "primevul" / "labels.jsonl", rows)
    loaded = load_primevul(tmp_path, subset=3)
    assert len(loaded) == 3
    assert [r.sample_id for r in loaded] == ["s0", "s1", "s2"]


@pytest.mark.asyncio
async def test_run_eval_with_stub_predictor(tmp_path: Path) -> None:
    rows = [
        {
            "sample_id": "s1",
            "file": "a.py",
            "line_start": 10,
            "line_end": 12,
            "cwe": "CWE-89",
        },
        {
            "sample_id": "s2",
            "file": "b.py",
            "line_start": 0,
            "line_end": 0,
            "vulnerable": False,
        },
    ]
    _write_jsonl(tmp_path / "primevul" / "labels.jsonl", rows)

    async def predict(gts: list[GroundTruth]) -> list[Prediction]:
        return [
            Prediction(
                sample_id="s1",
                file="a.py",
                line_start=10,
                line_end=12,
                cwe="CWE-89",
                confidence=0.9,
            )
        ]

    cfg = EvalConfig(name="test", dataset="primevul", subset=10, line_tolerance=0)
    run = await run_eval(cfg, predict, dataset_root=tmp_path)
    assert run.n_samples == 2
    assert run.n_predictions == 1
    # Perfect classifier on this tiny dataset.
    assert run.metrics["precision"] == 1.0
    assert run.metrics["recall"] == 1.0


def test_report_writers_emit_all_formats(tmp_path: Path) -> None:
    cfg = EvalConfig(name="x", dataset="primevul", subset=1)
    from datetime import UTC, datetime

    from coba.eval.schemas import EvalRun

    run = EvalRun(
        config=cfg,
        started_at=datetime.now(UTC),
        finished_at=datetime.now(UTC),
        n_samples=1,
        n_predictions=1,
        metrics={
            "precision": 1.0,
            "recall": 1.0,
            "f1": 1.0,
            "mcc": 1.0,
            "fp_rate": 0.0,
            "accuracy": 1.0,
        },
        cost_usd=0.0,
    )
    paths = write_all([run], tmp_path)
    for fmt in ("json", "markdown", "html", "csv"):
        assert paths[fmt].exists(), f"missing {fmt}"
        content = paths[fmt].read_text(encoding="utf-8")
        assert "x" in content
    # JSON parses
    data = json.loads(paths["json"].read_text(encoding="utf-8"))
    assert data["runs"][0]["config"]["name"] == "x"
    # HTML contains <table>
    assert "<table>" in paths["html"].read_text(encoding="utf-8")


def test_assemble_report_sets_generated_at() -> None:
    report = assemble_report([])
    assert report.runs == []
    assert report.generated_at is not None


def test_cli_smoke_writes_receipt(tmp_path: Path) -> None:
    """`run_cli` on an empty dataset still emits a receipt and report."""
    config_dir = tmp_path / "configs"
    output_dir = tmp_path / "results"
    dataset_root = tmp_path / "datasets"
    cfg = tmp_path / "configs" / "demo.yaml"
    config_dir.mkdir(parents=True)
    cfg.write_text(
        "name: demo\ndataset: primevul\nsubset: 5\nline_tolerance: 5\n",
        encoding="utf-8",
    )
    n = run_cli(
        config_dir=config_dir,
        dataset_root=dataset_root,
        output_dir=output_dir,
    )
    # No labels file → run skipped; receipt still written.
    receipt = output_dir / "_receipt.json"
    assert receipt.exists()
    body = json.loads(receipt.read_text(encoding="utf-8"))
    assert body["n_runs"] == n
