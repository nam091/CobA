"""Unit tests for ``coba.eval.matching.match_predictions``."""

from __future__ import annotations

from coba.eval.matching import match_predictions
from coba.eval.schemas import GroundTruth, Prediction


def _gt(
    sid: str,
    file: str,
    ls: int,
    le: int,
    cwe: str | None = "CWE-89",
    vuln: bool = True,
) -> GroundTruth:
    return GroundTruth(
        sample_id=sid,
        file=file,
        line_start=ls,
        line_end=le,
        cwe=cwe,
        vulnerable=vuln,
        dataset="test",
        language="python",
    )


def _pred(
    sid: str,
    file: str,
    ls: int,
    le: int,
    cwe: str = "CWE-89",
    conf: float = 0.9,
) -> Prediction:
    return Prediction(
        sample_id=sid, file=file, line_start=ls, line_end=le, cwe=cwe, confidence=conf
    )


def test_exact_match_is_tp() -> None:
    gts = [_gt("s1", "a.py", 10, 12)]
    preds = [_pred("s1", "a.py", 10, 12)]
    out = match_predictions(preds, gts, line_tolerance=0)
    assert (out.tp, out.fp, out.fn, out.tn) == (1, 0, 0, 0)


def test_line_tolerance() -> None:
    gts = [_gt("s1", "a.py", 10, 12)]
    # Off by 3 lines on each side; tolerance 5 should still match.
    preds = [_pred("s1", "a.py", 13, 15)]
    out = match_predictions(preds, gts, line_tolerance=5)
    assert out.tp == 1
    out_strict = match_predictions(preds, gts, line_tolerance=0)
    assert out_strict.tp == 0 and out_strict.fn == 1


def test_path_normalization() -> None:
    gts = [_gt("s1", "./src/A.py", 5, 5)]
    preds = [_pred("s1", "src/a.py", 5, 5)]
    out = match_predictions(preds, gts, line_tolerance=0)
    assert out.tp == 1


def test_cwe_mismatch_is_fn() -> None:
    gts = [_gt("s1", "a.py", 10, 12, cwe="CWE-89")]
    preds = [_pred("s1", "a.py", 10, 12, cwe="CWE-79")]
    out = match_predictions(preds, gts, require_cwe_match=True)
    assert out.tp == 0 and out.fn == 1 and out.fp == 1


def test_cwe_match_ignored_when_disabled() -> None:
    gts = [_gt("s1", "a.py", 10, 12, cwe="CWE-89")]
    preds = [_pred("s1", "a.py", 10, 12, cwe="CWE-79")]
    out = match_predictions(preds, gts, require_cwe_match=False)
    assert out.tp == 1


def test_negative_sample_with_prediction_is_fp() -> None:
    gts = [_gt("s1", "a.py", 0, 0, cwe=None, vuln=False)]
    preds = [_pred("s1", "a.py", 10, 10)]
    out = match_predictions(preds, gts)
    assert out.fp == 1 and out.tn == 0


def test_negative_sample_without_prediction_is_tn() -> None:
    gts = [_gt("s1", "a.py", 0, 0, cwe=None, vuln=False)]
    out = match_predictions([], gts)
    assert out.tn == 1


def test_multiple_predictions_on_same_gt_count_once() -> None:
    gts = [_gt("s1", "a.py", 10, 12)]
    preds = [
        _pred("s1", "a.py", 10, 12, conf=0.9),
        _pred("s1", "a.py", 11, 11, conf=0.8),
    ]
    out = match_predictions(preds, gts)
    assert out.tp == 1
    # The duplicate prediction is suppressed, not counted as extra FP.
    assert out.fp == 0


def test_prediction_on_unknown_sample_is_fp() -> None:
    gts = [_gt("s1", "a.py", 1, 1)]
    preds = [_pred("s2", "b.py", 1, 1)]
    out = match_predictions(preds, gts)
    assert out.fn == 1
    assert out.fp == 1
