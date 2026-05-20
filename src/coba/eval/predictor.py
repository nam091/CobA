"""Predictor that wraps :class:`coba.agent.loop.Orchestrator`.

The evaluation runner takes any async ``PredictFn`` (see
``coba.eval.runner.run_eval``). Until M3, the only built-in predictor
was a no-op that returned an empty list — useful for wiring tests but
not for measuring the real pipeline.

This module ships :class:`OrchestratorPredictor`, a thin adapter that:

* groups ground-truth samples by ``sample_id`` (which typically maps
  1:1 to a benchmark file like PrimeVul's ``samples/s001.c``);
* resolves each sample's path relative to ``dataset_root``;
* invokes ``Orchestrator.scan`` once per file (results are cached so
  that two samples pointing at the same path don't double-scan);
* turns every emitted :class:`coba.utils.schemas.Finding` into a
  :class:`coba.eval.schemas.Prediction` attributed to the originating
  ``sample_id``.

The predictor is async, callable, and stateless apart from an internal
per-call cache, so it composes naturally with ``run_eval`` and can be
swapped out by tests using :class:`MockOrchestrator` (any object with
an ``async scan`` method).
"""

from __future__ import annotations

from pathlib import Path
from typing import Protocol

from coba.eval.schemas import GroundTruth, Prediction
from coba.utils.logging import get_logger
from coba.utils.schemas import ScanReport, ScanRequest

log = get_logger("coba.eval.predictor")


class OrchestratorLike(Protocol):
    """Minimum interface a scanner must expose to be used as a predictor.

    The real :class:`coba.agent.loop.Orchestrator` satisfies this; tests
    use fakes that return canned :class:`ScanReport` objects without
    invoking real LLMs or SAST binaries.
    """

    async def scan(self, request: ScanRequest) -> ScanReport: ...


class OrchestratorPredictor:
    """Adapt :class:`Orchestrator` to the ``PredictFn`` signature."""

    def __init__(
        self,
        orchestrator: OrchestratorLike,
        *,
        dataset_root: Path,
        profile: str = "fast",
        no_cloud: bool = False,
    ) -> None:
        self._orch = orchestrator
        self._dataset_root = dataset_root
        self._profile = profile
        self._no_cloud = no_cloud
        self._cumulative_cost_usd = 0.0

    @property
    def cost_usd(self) -> float:
        """Cumulative LLM cost across the predictor's lifetime."""
        return self._cumulative_cost_usd

    async def __call__(self, gts: list[GroundTruth]) -> list[Prediction]:
        cache: dict[str, ScanReport] = {}
        preds: list[Prediction] = []
        total_cost = 0.0
        for gt in gts:
            target = self._resolve_target(gt)
            if target is None:
                log.warning(
                    "predictor.target_missing",
                    sample_id=gt.sample_id,
                    file=gt.file,
                )
                continue
            key = str(target)
            if key not in cache:
                report = await self._orch.scan(
                    ScanRequest(
                        target_path=str(target),
                        profile=self._profile,
                        no_cloud=self._no_cloud,
                    )
                )
                cache[key] = report
                if report.stats is not None:
                    total_cost += report.stats.total_cost_usd
            report = cache[key]
            preds.extend(self._findings_to_preds(report, gt))
        # Stash cumulative cost where the caller can pick it up via
        # ``cost_usd`` (purely informational; the runner does not require it).
        self._cumulative_cost_usd += total_cost
        log.info(
            "predictor.done",
            n_samples=len(gts),
            n_files=len(cache),
            n_preds=len(preds),
            cost_usd=round(total_cost, 4),
        )
        return preds

    # --------------------------------------------------------------- helpers
    def _resolve_target(self, gt: GroundTruth) -> Path | None:
        """Resolve the path to scan for a ground-truth sample.

        Tries (in order): ``<dataset_root>/<gt.file>``, then ``<gt.file>``
        as-is (in case the dataset uses absolute or pre-rooted paths).
        Returns ``None`` when neither exists.
        """
        candidate = self._dataset_root / gt.file
        if candidate.exists():
            return candidate.resolve()
        as_is = Path(gt.file)
        if as_is.exists():
            return as_is.resolve()
        return None

    @staticmethod
    def _findings_to_preds(report: ScanReport, gt: GroundTruth) -> list[Prediction]:
        """Map the scan's findings to predictions attributed to ``gt.sample_id``.

        ``Finding.file`` may be absolute (the orchestrator works in absolute
        paths). We normalise it back to the dataset-relative ``gt.file`` so
        the matcher's path comparison works regardless of where the dataset
        was downloaded.
        """
        out: list[Prediction] = []
        for f in report.findings:
            out.append(
                Prediction(
                    sample_id=gt.sample_id,
                    file=gt.file,
                    line_start=f.line_start,
                    line_end=f.line_end,
                    cwe=f.cwe,
                    confidence=f.confidence,
                    detector="coba",
                )
            )
        return out
