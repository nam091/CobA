"""CLI entry point used by ``coba eval``.

The eval command is intentionally light:

* It loads a YAML config from ``benchmarks/configs/<name>.yaml``.
* It resolves the dataset via :mod:`coba.eval.datasets`.
* It invokes :func:`coba.eval.runner.run_eval` with a prediction
  function that wraps :class:`coba.agent.loop.Orchestrator`.
* It writes a Markdown + JSON + HTML + CSV report into the output dir.

Until real datasets are available locally, the command logs a
"dataset unavailable" warning and still emits an (empty) report — which
is enough to keep CI green and let people see the wiring.
"""

from __future__ import annotations

import asyncio
import json
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


async def _run_async(
    config_paths: list[Path],
    dataset_root: Path,
    output_dir: Path,
) -> list[EvalRun]:
    runs: list[EvalRun] = []
    for cfg_path in config_paths:
        cfg = _load_yaml_config(cfg_path)
        log.info("eval.config", config=cfg.name, dataset=cfg.dataset, subset=cfg.subset)
        try:
            run = await run_eval(
                cfg,
                _zero_predict,
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
