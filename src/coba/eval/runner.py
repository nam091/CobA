"""Orchestrate one evaluation run: load dataset → predict → match → metrics."""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from datetime import UTC, datetime
from pathlib import Path

from coba.eval.datasets import DATASET_LOADERS, DatasetUnavailable
from coba.eval.matching import match_predictions
from coba.eval.metrics import ConfusionCounts, compute_metrics
from coba.eval.schemas import EvalConfig, EvalRun, GroundTruth, Prediction
from coba.utils.logging import get_logger

log = get_logger("coba.eval.runner")

PredictFn = Callable[[list[GroundTruth]], Awaitable[list[Prediction]]]
"""Async function that turns ground truth (list of sample_ids) into
predictions. Tests inject pure-Python fakes; production wires this to
:class:`coba.agent.loop.Orchestrator`."""


def _resolve_loader(name: str):
    try:
        return DATASET_LOADERS[name]
    except KeyError as exc:
        raise ValueError(
            f"Unknown dataset {name!r}; expected one of {sorted(DATASET_LOADERS)}"
        ) from exc


async def run_eval(
    config: EvalConfig,
    predict: PredictFn,
    *,
    dataset_root: Path,
    cost_usd: float = 0.0,
) -> EvalRun:
    """Execute one config x dataset combination.

    Args:
        config: which detector profile + dataset + tolerance to use.
        predict: async function turning ground-truth samples into
            predictions. Injected by the caller so tests can stub it
            without invoking real LLMs or SAST binaries.
        dataset_root: directory containing the benchmark datasets.
        cost_usd: optional accumulated cost; populated by the predict fn.

    Returns:
        :class:`EvalRun` with metrics and timings.
    """
    started = datetime.now(UTC)
    loader = _resolve_loader(config.dataset)
    try:
        gts: list[GroundTruth] = loader(dataset_root)
    except DatasetUnavailable:
        log.warning("eval.dataset_unavailable", dataset=config.dataset)
        return EvalRun(
            config=config,
            started_at=started,
            finished_at=datetime.now(UTC),
            n_samples=0,
            n_predictions=0,
            metrics={},
            cost_usd=cost_usd,
        )

    if config.subset and config.subset < len(gts):
        gts = gts[: config.subset]

    preds = await predict(gts)
    outcome = match_predictions(
        preds,
        gts,
        line_tolerance=config.line_tolerance,
        require_cwe_match=config.require_cwe_match,
    )
    metrics = compute_metrics(
        ConfusionCounts(tp=outcome.tp, fp=outcome.fp, fn=outcome.fn, tn=outcome.tn)
    )
    log.info(
        "eval.done",
        config=config.name,
        dataset=config.dataset,
        n=len(gts),
        precision=round(metrics.precision, 3),
        recall=round(metrics.recall, 3),
        f1=round(metrics.f1, 3),
    )
    return EvalRun(
        config=config,
        started_at=started,
        finished_at=datetime.now(UTC),
        n_samples=len(gts),
        n_predictions=len(preds),
        metrics={
            **metrics.to_dict(),
            "tp": float(outcome.tp),
            "fp": float(outcome.fp),
            "fn": float(outcome.fn),
            "tn": float(outcome.tn),
        },
        cost_usd=cost_usd,
    )
