"""Unit tests for ``coba.eval.metrics``."""

from __future__ import annotations

import math

from coba.eval.metrics import ConfusionCounts, compute_metrics


def test_perfect_classifier() -> None:
    m = compute_metrics(ConfusionCounts(tp=10, fp=0, fn=0, tn=10))
    assert m.precision == 1.0
    assert m.recall == 1.0
    assert m.f1 == 1.0
    assert m.mcc == 1.0
    assert m.fp_rate == 0.0
    assert m.accuracy == 1.0


def test_all_wrong_classifier() -> None:
    m = compute_metrics(ConfusionCounts(tp=0, fp=10, fn=10, tn=0))
    assert m.precision == 0.0
    assert m.recall == 0.0
    assert m.f1 == 0.0
    # Pure anti-classifier: every prediction is inverted → MCC = -1.0.
    assert math.isclose(m.mcc, -1.0, abs_tol=1e-9)
    assert m.fp_rate == 1.0
    assert m.accuracy == 0.0


def test_balanced_classifier() -> None:
    # TP=8, FP=2, FN=2, TN=8 → P=0.8, R=0.8, F1=0.8, accuracy=0.8
    m = compute_metrics(ConfusionCounts(tp=8, fp=2, fn=2, tn=8))
    assert math.isclose(m.precision, 0.8, abs_tol=1e-9)
    assert math.isclose(m.recall, 0.8, abs_tol=1e-9)
    assert math.isclose(m.f1, 0.8, abs_tol=1e-9)
    assert math.isclose(m.fp_rate, 0.2, abs_tol=1e-9)
    assert math.isclose(m.accuracy, 0.8, abs_tol=1e-9)
    # MCC = (64-4) / sqrt(10 * 10 * 10 * 10) = 60/100 = 0.6
    assert math.isclose(m.mcc, 0.6, abs_tol=1e-9)


def test_no_predictions() -> None:
    """Predictor that emits nothing → P=0, R=0, F1=0; no NaN."""
    m = compute_metrics(ConfusionCounts(tp=0, fp=0, fn=5, tn=10))
    assert m.precision == 0.0
    assert m.recall == 0.0
    assert m.f1 == 0.0
    assert m.fp_rate == 0.0
    assert math.isfinite(m.mcc)


def test_no_negative_samples() -> None:
    """All samples are positive → fp_rate is 0 (denominator 0)."""
    m = compute_metrics(ConfusionCounts(tp=5, fp=0, fn=5, tn=0))
    assert m.fp_rate == 0.0
    assert m.mcc == 0.0  # denominator includes (tn+fp) = 0


def test_to_dict_roundtrip() -> None:
    m = compute_metrics(ConfusionCounts(tp=1, fp=1, fn=1, tn=1))
    d = m.to_dict()
    assert set(d) == {"precision", "recall", "f1", "mcc", "fp_rate", "accuracy"}
    assert all(isinstance(v, float) for v in d.values())
