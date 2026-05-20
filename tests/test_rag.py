"""Unit tests for the built-in RAG index."""

from coba.agent.rag import RagIndex


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
