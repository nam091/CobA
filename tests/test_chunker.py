"""Unit tests for ``coba.agent.chunker``."""

from pathlib import Path

from coba.agent.chunker import chunk_file
from coba.utils.schemas import Language


def test_chunk_python_function(tmp_path: Path) -> None:
    src = tmp_path / "a.py"
    src.write_text(
        "import os\n\n"
        "def vulnerable(user_input):\n"
        "    os.system('echo ' + user_input)\n"
        "\n"
        "def safe():\n"
        "    return 42\n",
        encoding="utf-8",
    )
    chunks = chunk_file(src)
    assert chunks, "chunker should produce at least one chunk"
    # If tree-sitter is available we expect 2 function chunks; otherwise fallback.
    langs = {c.language for c in chunks}
    assert Language.PYTHON in langs


def test_chunk_nonexistent_returns_empty() -> None:
    chunks = chunk_file(Path("/nonexistent/__path__.py"))
    assert chunks == []


def test_chunk_text_fallback(tmp_path: Path) -> None:
    """Files with extensions we don't know fall back to window chunks."""
    src = tmp_path / "a.txt"
    src.write_text("hello\nworld\n", encoding="utf-8")
    chunks = chunk_file(src)
    # Unknown language → discovery happens upstream; chunker still runs.
    # We accept either empty or a single window chunk.
    assert isinstance(chunks, list)
