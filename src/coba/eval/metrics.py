"""Compute precision, recall, F1, MCC, FP rate and a few helpers."""

from __future__ import annotations

import math
from dataclasses import asdict, dataclass


@dataclass(frozen=True)
class ConfusionCounts:
    tp: int = 0
    fp: int = 0
    fn: int = 0
    tn: int = 0


@dataclass(frozen=True)
class EvalMetrics:
    precision: float = 0.0
    recall: float = 0.0
    f1: float = 0.0
    mcc: float = 0.0
    fp_rate: float = 0.0
    accuracy: float = 0.0

    def to_dict(self) -> dict[str, float]:
        return asdict(self)


def _safe_div(num: float, den: float) -> float:
    return num / den if den else 0.0


def compute_metrics(counts: ConfusionCounts) -> EvalMetrics:
    """Return precision, recall, F1, MCC, FP-rate, accuracy.

    The implementation follows the textbook definitions in
    ``docs/08_EVALUATION.md`` § 1.2. All metrics return 0.0 on undefined
    inputs (e.g. P with no predictions) — never NaN or ``ZeroDivisionError``.
    MCC additionally avoids the classic ``sqrt(0)`` overflow.
    """
    tp, fp, fn, tn = counts.tp, counts.fp, counts.fn, counts.tn
    precision = _safe_div(tp, tp + fp)
    recall = _safe_div(tp, tp + fn)
    f1 = _safe_div(2 * precision * recall, precision + recall) if precision + recall else 0.0
    fp_rate = _safe_div(fp, fp + tn)
    accuracy = _safe_div(tp + tn, tp + fp + fn + tn)
    denom_sq = (tp + fp) * (tp + fn) * (tn + fp) * (tn + fn)
    mcc = (tp * tn - fp * fn) / math.sqrt(denom_sq) if denom_sq > 0 else 0.0
    return EvalMetrics(
        precision=precision,
        recall=recall,
        f1=f1,
        mcc=mcc,
        fp_rate=fp_rate,
        accuracy=accuracy,
    )
