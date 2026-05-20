"""Match predictions against ground truth, producing a confusion matrix.

A prediction is a *true positive* when:
  * the ground-truth sample is vulnerable;
  * file paths match (normalised);
  * line ranges overlap, with the ground-truth interval inflated by
    ``line_tolerance`` lines on each side;
  * when ``require_cwe_match`` is true, the top-level CWE id matches.

Multiple predictions hitting the same ground truth count as **one** TP;
extra predictions on that sample do *not* become FPs (they are
de-duplicated). Predictions on negative samples become FPs. Ground
truths with zero matching predictions become FNs. Negative samples with
zero predictions become TNs.
"""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Sequence
from dataclasses import dataclass

from coba.eval.schemas import GroundTruth, Prediction


@dataclass(frozen=True)
class MatchOutcome:
    """Outcome of matching predictions against ground truth."""

    tp: int = 0
    fp: int = 0
    fn: int = 0
    tn: int = 0
    matched_pairs: tuple[tuple[str, str], ...] = ()
    """Pairs of ``(sample_id, prediction_index)`` that were matched."""


def _norm_path(p: str) -> str:
    """Lowercase + strip leading ``./``; sufficient for evaluation
    matching (datasets already use consistent relative paths)."""
    p = p.replace("\\", "/").lstrip("./")
    return p.lower()


def _ranges_overlap(
    pred_start: int,
    pred_end: int,
    gt_start: int,
    gt_end: int,
    tolerance: int,
) -> bool:
    lo = gt_start - tolerance
    hi = gt_end + tolerance
    return pred_end >= lo and pred_start <= hi


def _cwe_match(pred_cwe: str, gt_cwe: str | None) -> bool:
    if gt_cwe is None:
        return False
    return pred_cwe.strip().upper() == gt_cwe.strip().upper()


def match_predictions(
    predictions: Sequence[Prediction],
    ground_truth: Sequence[GroundTruth],
    *,
    line_tolerance: int = 5,
    require_cwe_match: bool = True,
) -> MatchOutcome:
    """Compute (TP, FP, FN, TN) for one dataset.

    Args:
        predictions: detector findings.
        ground_truth: dataset labels.
        line_tolerance: each ground-truth line range is inflated by this
            many lines on each side before overlap testing.
        require_cwe_match: when True, predictions must cite the same
            top-level CWE id as the label.

    Returns:
        :class:`MatchOutcome` with raw counts and matched pairs.
    """
    gt_by_sample: dict[str, list[GroundTruth]] = defaultdict(list)
    for gt in ground_truth:
        gt_by_sample[gt.sample_id].append(gt)

    pred_by_sample: dict[str, list[Prediction]] = defaultdict(list)
    for p in predictions:
        pred_by_sample[p.sample_id].append(p)

    tp = fp = fn = tn = 0
    matched: list[tuple[str, str]] = []
    seen_gt: set[tuple[str, int]] = set()

    for sample_id, gts in gt_by_sample.items():
        preds = pred_by_sample.get(sample_id, [])
        any_vuln = any(g.vulnerable for g in gts)

        if not any_vuln:
            if preds:
                fp += len(preds)
            else:
                tn += 1
            continue

        for idx, gt in enumerate(gts):
            if not gt.vulnerable:
                continue
            hit = False
            for p in preds:
                if _norm_path(p.file) != _norm_path(gt.file):
                    continue
                if not _ranges_overlap(
                    p.line_start, p.line_end, gt.line_start, gt.line_end, line_tolerance
                ):
                    continue
                if require_cwe_match and not _cwe_match(p.cwe, gt.cwe):
                    continue
                hit = True
                matched.append((sample_id, f"{idx}"))
                seen_gt.add((sample_id, idx))
                break
            if hit:
                tp += 1
            else:
                fn += 1

        for p in preds:
            matched_this_pred = False
            for idx, gt in enumerate(gts):
                if not gt.vulnerable or (sample_id, idx) not in seen_gt:
                    continue
                if _norm_path(p.file) != _norm_path(gt.file):
                    continue
                if not _ranges_overlap(
                    p.line_start, p.line_end, gt.line_start, gt.line_end, line_tolerance
                ):
                    continue
                if require_cwe_match and not _cwe_match(p.cwe, gt.cwe):
                    continue
                matched_this_pred = True
                break
            if not matched_this_pred:
                fp += 1

    # Predictions on samples with no ground truth at all → unmatched FPs.
    for sample_id, preds in pred_by_sample.items():
        if sample_id in gt_by_sample:
            continue
        fp += len(preds)

    return MatchOutcome(tp=tp, fp=fp, fn=fn, tn=tn, matched_pairs=tuple(matched))
