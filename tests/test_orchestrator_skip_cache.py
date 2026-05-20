"""Integration test: Orchestrator's skip-cache wiring.

We avoid going through the full ``scan()`` (which needs LLM credentials)
by exercising the two private helpers ``_apply_skip_cache`` and
``_persist_skip_cache`` directly. They are the entire surface area of
the M3c cache behaviour.
"""

from __future__ import annotations

from pathlib import Path

from coba.agent.loop import Orchestrator, _normalize_file_key
from coba.agent.skip_cache import SkipCache, SkipCacheRecord
from coba.utils.schemas import Chunk, Finding, Language, Severity, Verdict


def _mk_finding(path: Path, line: int = 5) -> Finding:
    return Finding(
        file=str(path),
        function="login",
        line_start=line,
        line_end=line,
        cwe="CWE-89",
        severity=Severity.HIGH,
        confidence=0.9,
        title="SQL injection",
        description="...",
        data_flow=[],
        fix_suggestion="parameterize",
        sources=["llm-detector"],
        verifier_verdict=Verdict.TRUE_POSITIVE,
        verifier_rationale="ok",
    )


def _mk_chunk(path: Path) -> Chunk:
    return Chunk(
        file=str(path),
        language=Language.PYTHON,
        function="login",
        line_start=1,
        line_end=10,
        body="...",
    )


def _orch_with_cache(tmp_cache: Path) -> Orchestrator:
    """Build an Orchestrator with no SAST tools, isolated cache root."""
    orch = Orchestrator.__new__(Orchestrator)
    orch.settings = type("S", (), {"cache_dir": tmp_cache, "coba_skip_cache_enabled": True})()
    orch.skip_cache = SkipCache(tmp_cache, enabled=True)
    return orch


def test_apply_skip_cache_returns_cached_findings(tmp_path: Path) -> None:
    src = tmp_path / "a.py"
    src.write_bytes(b"print('hi')\n")
    cache_root = tmp_path / "cache"
    orch = _orch_with_cache(cache_root)

    # Seed the cache with one finding tied to src's actual hash.
    from coba.agent.skip_cache import hash_file

    real_sha = hash_file(src)
    assert real_sha is not None
    orch.skip_cache.put(
        SkipCacheRecord.from_findings(real_sha, _normalize_file_key(str(src)), [_mk_finding(src)])
    )

    cached, to_scan, hashes = orch._apply_skip_cache([src], [_mk_chunk(src)])
    assert len(cached) == 1
    assert to_scan == []
    assert hashes[_normalize_file_key(str(src))] == real_sha


def test_apply_skip_cache_misses_when_file_changes(tmp_path: Path) -> None:
    src = tmp_path / "a.py"
    src.write_bytes(b"v1\n")
    cache_root = tmp_path / "cache"
    orch = _orch_with_cache(cache_root)

    from coba.agent.skip_cache import hash_file

    old_sha = hash_file(src)
    assert old_sha is not None
    orch.skip_cache.put(
        SkipCacheRecord.from_findings(old_sha, _normalize_file_key(str(src)), [_mk_finding(src)])
    )
    # Mutate the file -> hash changes -> cache miss.
    src.write_bytes(b"v2\n")

    cached, to_scan, hashes = orch._apply_skip_cache([src], [_mk_chunk(src)])
    assert cached == []
    assert len(to_scan) == 1
    assert _normalize_file_key(str(src)) in hashes


def test_persist_skip_cache_writes_fresh_findings_only(tmp_path: Path) -> None:
    src = tmp_path / "a.py"
    src.write_bytes(b"v1\n")
    cache_root = tmp_path / "cache"
    orch = _orch_with_cache(cache_root)

    from coba.agent.skip_cache import hash_file

    sha = hash_file(src)
    assert sha is not None
    finding = _mk_finding(src)
    orch._persist_skip_cache(
        all_findings=[finding],
        chunks_scanned=[_mk_chunk(src)],
        file_hashes={_normalize_file_key(str(src)): sha},
        cached_findings=[],
    )

    rec = orch.skip_cache.get(sha)
    assert rec is not None
    assert rec.n_findings == 1


def test_persist_skip_cache_caches_empty_clean_files(tmp_path: Path) -> None:
    """A scanned file with zero findings must still be cached as 'clean'."""
    src = tmp_path / "clean.py"
    src.write_bytes(b"a = 1\n")
    cache_root = tmp_path / "cache"
    orch = _orch_with_cache(cache_root)

    from coba.agent.skip_cache import hash_file

    sha = hash_file(src)
    assert sha is not None
    orch._persist_skip_cache(
        all_findings=[],
        chunks_scanned=[_mk_chunk(src)],
        file_hashes={_normalize_file_key(str(src)): sha},
        cached_findings=[],
    )
    rec = orch.skip_cache.get(sha)
    assert rec is not None
    assert rec.n_findings == 0


def test_persist_skip_cache_does_not_duplicate_cached_findings(tmp_path: Path) -> None:
    """Cached findings must NOT be re-persisted (would double them up)."""
    src = tmp_path / "a.py"
    src.write_bytes(b"v\n")
    cache_root = tmp_path / "cache"
    orch = _orch_with_cache(cache_root)

    from coba.agent.skip_cache import hash_file

    sha = hash_file(src)
    assert sha is not None
    cached_f = _mk_finding(src)
    fresh_f = _mk_finding(src, line=99)
    # `all_findings` contains both cached + fresh (as the orchestrator merges).
    orch._persist_skip_cache(
        all_findings=[cached_f, fresh_f],
        chunks_scanned=[_mk_chunk(src)],
        file_hashes={_normalize_file_key(str(src)): sha},
        cached_findings=[cached_f],
    )
    rec = orch.skip_cache.get(sha)
    assert rec is not None
    # Only the fresh one persisted; cached one not duplicated.
    assert rec.n_findings == 1
    assert rec.to_findings()[0].line_start == 99
