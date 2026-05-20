"""Evaluation framework — datasets, metrics, runner, report.

This package implements the skeleton described in
``docs/08_EVALUATION.md`` and ``report/Chuong_6_Danh_gia.md``. The
actual benchmark runs require external datasets (PrimeVul, OWASP
Benchmark, Juliet) downloaded via ``scripts/download_datasets.sh`` — the
package itself is fully self-contained and unit-tested in offline mode.
"""

from coba.eval.matching import match_predictions
from coba.eval.metrics import ConfusionCounts, EvalMetrics, compute_metrics
from coba.eval.schemas import EvalConfig, EvalReport, EvalRun, GroundTruth, Prediction

__all__ = [
    "ConfusionCounts",
    "EvalConfig",
    "EvalMetrics",
    "EvalReport",
    "EvalRun",
    "GroundTruth",
    "Prediction",
    "compute_metrics",
    "match_predictions",
]
