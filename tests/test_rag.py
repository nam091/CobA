"""Unit tests for the built-in RAG index."""

from pathlib import Path

import pytest

from coba.agent.rag import ChromaRagIndex, RagIndex, load_rag_index


def test_by_cwe_lookup() -> None:
    idx = RagIndex()
    assert idx.by_cwe("CWE-89") is not None
    assert idx.by_cwe("CWE-99999") is None


def test_query_matches_keywords() -> None:
    idx = RagIndex()
    results = idx.query(hints=["sql injection"], top_k=3)
    assert any(r.cwe_id == "CWE-89" for r in results)


def test_query_empty_returns_some() -> None:
    idx = RagIndex()
    results = idx.query(hints=[], top_k=2)
    assert len(results) == 2


def test_load_rag_index_falls_back_to_builtin(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """If the Chroma persist dir is empty, ``load_rag_index`` returns the
    in-memory builtin rather than crashing."""
    # Point settings at an empty tmp dir.
    from coba.config import settings as settings_module

    cached = settings_module.get_settings()
    monkeypatch.setattr(cached, "chroma_persist_dir", tmp_path)
    idx = load_rag_index()
    assert isinstance(idx, RagIndex)
    assert not isinstance(idx, ChromaRagIndex)
    assert idx.by_cwe("CWE-89") is not None
