"""CLI entry point used by ``coba eval``.

The eval command is intentionally light:

* It loads a YAML config from ``benchmarks/configs/<name>.yaml``.
* It resolves the dataset via :mod:`coba.eval.datasets`.
* It picks a predictor:

  - ``predictor: zero`` (default) — emits no findings; useful for CI
    smoke tests because it never touches LLMs or SAST binaries.
  - ``predictor: orchestrator`` — wires the real
    :class:`coba.agent.loop.Orchestrator` through
    :class:`coba.eval.predictor.OrchestratorPredictor`. Requires either
    a configured LLM API key or local Ollama (see ``docs/06``).

* It invokes :func:`coba.eval.runner.run_eval`.
* It writes a Markdown + JSON + HTML + CSV report into the output dir.

Until real datasets are available locally, the command logs a
"dataset unavailable" warning and still emits an (empty) report — which
is enough to keep CI green and let people see the wiring.
"""

from __future__ import annotations

import asyncio
import json
from collections.abc import Awaitable, Callable
from pathlib import Path

import yaml

from coba.eval.datasets import DatasetUnavailable
from coba.eval.report import write_all
from coba.eval.runner import run_eval
from coba.eval.schemas import EvalConfig, EvalRun, GroundTruth, Prediction
from coba.utils.logging import get_logger

log = get_logger("coba.eval.cli")

DEFAULT_CONFIG_DIR = Path("benchmarks/configs")
DEFAULT_DATASET_ROOT = Path("benchmarks/datasets")
DEFAULT_OUTPUT_DIR = Path("benchmarks/results")


def _load_yaml_config(path: Path) -> EvalConfig:
    with path.open("r", encoding="utf-8") as f:
        data = yaml.safe_load(f) or {}
    return EvalConfig.model_validate(data)


async def _zero_predict(_gts: list[GroundTruth]) -> list[Prediction]:
    """Default predictor for the wiring: emits zero predictions."""
    return []


PredictFn = Callable[[list[GroundTruth]], Awaitable[list[Prediction]]]


def _resolve_predictor(cfg: EvalConfig, dataset_root: Path) -> PredictFn:
    """Map ``cfg.predictor`` to an async predictor function.

    Imports of the heavy ``coba.agent.loop`` module are deferred so the
    eval CLI starts quickly even when only the zero predictor is used
    (Orchestrator pulls in Tree-sitter, Joern, RAG, etc.).
    """
    name = (cfg.predictor or "zero").lower()
    if name == "zero":
        return _zero_predict
    if name == "orchestrator":
        from coba.agent.loop import Orchestrator
        from coba.eval.predictor import OrchestratorPredictor

        orchestrator = Orchestrator()
        return OrchestratorPredictor(
            orchestrator,
            dataset_root=dataset_root,
            profile=cfg.detector_profile,
            no_cloud=cfg.no_cloud,
        )
    raise ValueError(f"Unknown predictor {name!r}; expected one of 'zero', 'orchestrator'.")


async def _run_async(
    config_paths: list[Path],
    dataset_root: Path,
    output_dir: Path,
) -> list[EvalRun]:
    runs: list[EvalRun] = []
    for cfg_path in config_paths:
        cfg = _load_yaml_config(cfg_path)
        log.info(
            "eval.config",
            config=cfg.name,
            dataset=cfg.dataset,
            subset=cfg.subset,
            predictor=cfg.predictor,
        )
        predict = _resolve_predictor(cfg, dataset_root)
        try:
            run = await run_eval(
                cfg,
                predict,
                dataset_root=dataset_root,
            )
        except DatasetUnavailable as exc:
            log.warning("eval.dataset_unavailable", config=cfg.name, error=str(exc))
            continue
        runs.append(run)
    paths = write_all(runs, output_dir)
    log.info("eval.report_written", paths={k: str(v) for k, v in paths.items()})
    return runs


def run_cli(
    *,
    configs: list[str] | None = None,
    config_dir: Path = DEFAULT_CONFIG_DIR,
    dataset_root: Path = DEFAULT_DATASET_ROOT,
    output_dir: Path = DEFAULT_OUTPUT_DIR,
) -> int:
    """Entry point invoked by :func:`coba.cli.main.eval_cmd`.

    Resolves YAML configs (default: every ``.yaml`` in ``config_dir``)
    then awaits :func:`_run_async`. Returns the number of runs.
    """
    config_dir.mkdir(parents=True, exist_ok=True)
    output_dir.mkdir(parents=True, exist_ok=True)

    if configs:
        paths = [config_dir / f"{name}.yaml" for name in configs]
    else:
        paths = sorted(config_dir.glob("*.yaml"))

    missing = [p for p in paths if not p.exists()]
    if missing:
        log.error("eval.config_missing", missing=[str(p) for p in missing])
        return 0

    if not paths:
        log.warning("eval.no_configs", config_dir=str(config_dir))
        return 0

    runs = asyncio.run(_run_async(paths, dataset_root, output_dir))
    # A small machine-readable receipt for shell scripts.
    receipt = {
        "n_runs": len(runs),
        "configs": [r.config.name for r in runs],
        "output_dir": str(output_dir),
    }
    (output_dir / "_receipt.json").write_text(json.dumps(receipt, indent=2), encoding="utf-8")
    return len(runs)
