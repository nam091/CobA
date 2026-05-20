"""Unit tests for SkipCache + hash_file."""

from __future__ import annotations

import json
from pathlib import Path

from coba.agent.skip_cache import SkipCache, SkipCacheRecord, hash_file
from coba.utils.schemas import Finding, Severity, Verdict


def _mk_finding(file: str = "demo.py", line: int = 10) -> Finding:
    return Finding(
        file=file,
        function="login",
        line_start=line,
        line_end=line + 2,
        cwe="CWE-89",
        severity=Severity.HIGH,
        confidence=0.85,
        title="SQL injection",
        description="String concat into SQL.",
        data_flow=[],
        fix_suggestion="Use parameterized queries.",
        sources=["llm-detector"],
        verifier_verdict=Verdict.TRUE_POSITIVE,
        verifier_rationale="Confirmed by verifier",
    )


def test_hash_file_returns_consistent_digest(tmp_path: Path) -> None:
    f = tmp_path / "a.py"
    f.write_bytes(b"print('hi')\n")
    h1 = hash_file(f)
    h2 = hash_file(f)
    assert h1 is not None and len(h1) == 64
    assert h1 == h2


def test_hash_file_changes_when_content_changes(tmp_path: Path) -> None:
    f = tmp_path / "a.py"
    f.write_bytes(b"v1\n")
    h1 = hash_file(f)
    f.write_bytes(b"v2\n")
    h2 = hash_file(f)
    assert h1 != h2


def test_hash_file_missing_returns_none(tmp_path: Path) -> None:
    assert hash_file(tmp_path / "missing.py") is None


def test_skip_cache_miss_returns_none(tmp_path: Path) -> None:
    cache = SkipCache(tmp_path)
    assert cache.get("deadbeef" * 8) is None
    assert cache.stats()["misses"] == 1


def test_skip_cache_roundtrip(tmp_path: Path) -> None:
    cache = SkipCache(tmp_path)
    finding = _mk_finding()
    rec = SkipCacheRecord.from_findings("a" * 64, "demo.py", [finding])
    cache.put(rec)
    got = cache.get("a" * 64)
    assert got is not None
    assert got.n_findings == 1
    restored = got.to_findings()
    assert len(restored) == 1
    assert restored[0].cwe == "CWE-89"
    assert restored[0].file == "demo.py"
    assert cache.stats()["writes"] == 1
    assert cache.stats()["hits"] == 1


def test_skip_cache_disabled_no_io(tmp_path: Path) -> None:
    cache = SkipCache(tmp_path, enabled=False)
    cache.put(SkipCacheRecord.from_findings("b" * 64, "demo.py", []))
    assert cache.get("b" * 64) is None
    # Disabled cache should not have created any files
    assert not (tmp_path / "skip").exists()


def test_skip_cache_invalid_schema_treated_as_miss(tmp_path: Path) -> None:
    cache = SkipCache(tmp_path)
    sha = "c" * 64
    path = cache._path_for(sha)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({"schema_version": "bogus.v0"}), encoding="utf-8")
    assert cache.get(sha) is None


def test_skip_cache_corrupt_json_treated_as_miss(tmp_path: Path) -> None:
    cache = SkipCache(tmp_path)
    sha = "d" * 64
    path = cache._path_for(sha)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("{not-json", encoding="utf-8")
    assert cache.get(sha) is None


def test_skip_cache_empty_findings_still_persisted(tmp_path: Path) -> None:
    """A clean file (no findings) must still be cached so we don't rescan."""
    cache = SkipCache(tmp_path)
    sha = "e" * 64
    cache.put(SkipCacheRecord.from_findings(sha, "clean.py", []))
    rec = cache.get(sha)
    assert rec is not None
    assert rec.n_findings == 0
    assert rec.to_findings() == []
