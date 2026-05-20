"""Dataset loaders for evaluation benchmarks.

Each loader reads from a local directory under ``benchmarks/datasets/`` —
populated either via ``scripts/download_datasets.sh`` or, for tests, via
fixture files. Loaders return ``(ground_truth, sample_paths)`` where
``sample_paths`` is the list of source files to scan.

PrimeVul, OWASP Benchmark and Juliet are stub-loadable here: the
*signature* and *normalization* are real; the network download and
parsing of the original archives is left as M4 work, with a clear
TODO. Tests inject synthetic JSONL fixtures so the eval pipeline is
fully testable today.
"""

from __future__ import annotations

import json
from pathlib import Path

from coba.eval.schemas import GroundTruth
from coba.utils.logging import get_logger

log = get_logger("coba.eval.datasets")


class DatasetUnavailable(RuntimeError):
    """Raised when a dataset has not been downloaded yet."""


def load_jsonl_dataset(path: Path, dataset_name: str) -> list[GroundTruth]:
    """Load a JSONL file of ``GroundTruth`` records.

    Each line is a JSON object with the schema in
    :class:`coba.eval.schemas.GroundTruth`. Used by all three benchmark
    loaders below after they normalize their native formats. Tests
    inject fixtures using this loader directly.
    """
    if not path.exists():
        raise DatasetUnavailable(
            f"Dataset file not found: {path}. Run `bash scripts/download_datasets.sh` first."
        )
    out: list[GroundTruth] = []
    with path.open("r", encoding="utf-8") as f:
        for i, raw in enumerate(f, 1):
            raw = raw.strip()
            if not raw or raw.startswith("//"):
                continue
            try:
                obj = json.loads(raw)
            except json.JSONDecodeError as exc:
                log.warning("dataset.bad_line", line=i, error=str(exc))
                continue
            obj.setdefault("dataset", dataset_name)
            out.append(GroundTruth.model_validate(obj))
    log.info("dataset.loaded", name=dataset_name, count=len(out))
    return out


def load_primevul(root: Path, subset: int | None = None) -> list[GroundTruth]:
    """Load PrimeVul ground-truth records.

    Reads from ``<root>/primevul/labels.jsonl`` (populated by
    ``scripts/download_datasets.sh primevul``). Lines beyond ``subset``
    are dropped.
    """
    path = root / "primevul" / "labels.jsonl"
    rows = load_jsonl_dataset(path, "primevul")
    return rows[:subset] if subset is not None else rows


def load_owasp_benchmark(root: Path) -> list[GroundTruth]:
    """Load OWASP Benchmark Java labels."""
    path = root / "owasp_benchmark" / "labels.jsonl"
    return load_jsonl_dataset(path, "owasp_benchmark")


def load_juliet(root: Path) -> list[GroundTruth]:
    """Load Juliet C/C++/Java labels."""
    path = root / "juliet" / "labels.jsonl"
    return load_jsonl_dataset(path, "juliet")


DATASET_LOADERS = {
    "primevul": load_primevul,
    "owasp": load_owasp_benchmark,
    "owasp_benchmark": load_owasp_benchmark,
    "juliet": load_juliet,
}
