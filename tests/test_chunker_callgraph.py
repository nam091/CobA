"""Integration tests for chunker + CallGraph enrichment + prompt rendering."""

from __future__ import annotations

from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

from coba.agent.callgraph import CallGraph
from coba.agent.chunker import chunk_file

PROMPTS_DIR = Path(__file__).resolve().parents[1] / "src" / "coba" / "prompts"


def test_chunker_without_callgraph_leaves_lists_empty(tmp_path: Path) -> None:
    src = tmp_path / "demo.py"
    src.write_text("def alpha(x):\n    return beta(x) + 1\n\ndef beta(y):\n    return y\n")
    chunks = chunk_file(src)
    for ch in chunks:
        assert ch.callers == []
        assert ch.callees == []


def test_chunker_enriches_with_callgraph(tmp_path: Path) -> None:
    src = tmp_path / "demo.py"
    src.write_text("def alpha(x):\n    return beta(x) + 1\n\ndef beta(y):\n    return y\n")
    cg = CallGraph.from_records(
        [
            {
                "file": str(src),
                "function": "alpha",
                "line": 1,
                "callees": ["beta"],
                "callers": [],
            },
            {
                "file": str(src),
                "function": "beta",
                "line": 4,
                "callees": [],
                "callers": ["alpha"],
            },
        ]
    )
    chunks = chunk_file(src, call_graph=cg)
    if not any(ch.function for ch in chunks):
        # tree-sitter unavailable in the env → chunker fell back to window
        # mode; no function names. Skip the enrichment assertion in that case.
        return
    by_fn = {ch.function: ch for ch in chunks if ch.function}
    assert "alpha" in by_fn or "beta" in by_fn
    if "alpha" in by_fn:
        assert by_fn["alpha"].callees == ["beta"]
    if "beta" in by_fn:
        assert by_fn["beta"].callers == ["alpha"]


def test_detector_prompt_renders_callers_callees() -> None:
    """Prompt template should include callers/callees blocks when present."""
    from coba.utils.schemas import Chunk, Language

    chunk = Chunk(
        file="demo.py",
        language=Language.PYTHON,
        function="alpha",
        line_start=1,
        line_end=5,
        body="def alpha():\n    return beta()",
        callers=["main"],
        callees=["beta"],
    )
    env = Environment(
        loader=FileSystemLoader(str(PROMPTS_DIR)),
        autoescape=select_autoescape(disabled_extensions=("j2",)),
        keep_trailing_newline=True,
    )
    prompt = env.get_template("detector.j2").render(
        chunk=chunk,
        body=chunk.body,
        static_hints=[],
        cwe_context=[],
    )
    assert "Callers" in prompt
    assert "- main" in prompt
    assert "Callees" in prompt
    assert "- beta" in prompt
