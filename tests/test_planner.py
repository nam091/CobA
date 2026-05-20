"""Unit tests for ``coba.agent.planner``."""

from pathlib import Path

from coba.agent.planner import Planner
from coba.utils.schemas import Language


def test_planner_discovers_python(tmp_path: Path) -> None:
    (tmp_path / "a.py").write_text("def f(): pass\n")
    (tmp_path / "b.txt").write_text("not source\n")
    (tmp_path / "node_modules").mkdir()
    (tmp_path / "node_modules" / "skip.py").write_text("def s(): pass\n")

    p = Planner(languages=[Language.PYTHON])
    files = p.discover_files(tmp_path)
    paths = {f.name for f in files}
    assert "a.py" in paths
    assert "b.txt" not in paths
    assert "skip.py" not in paths


def test_planner_chunks_files(tmp_path: Path) -> None:
    (tmp_path / "a.py").write_text(
        "def add(a, b):\n    return a + b\n\ndef sub(a, b):\n    return a - b\n",
        encoding="utf-8",
    )
    p = Planner()
    files, chunks = p.plan(tmp_path)
    assert len(files) == 1
    assert len(chunks) >= 1
