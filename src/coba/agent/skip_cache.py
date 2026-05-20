"""Skip-cache — content-addressed cache of finalized findings per file.

The goal is to avoid re-running the (expensive) LLM Detector + Verifier on
files whose content has not changed since the last scan. We hash the raw
bytes of each file, look up a record under ``<cache_dir>/skip/<sha>.json``,
and if present reuse its findings; otherwise we let the normal pipeline
run and persist the new record at the end.

The cache is intentionally simple and best-effort:
- Stale entries are tolerated (we just skip them on read errors).
- We do not garbage-collect — disk usage is bounded by the number of
  distinct file revisions ever scanned. For the v0 prototype this is
  acceptable; M4 may add a TTL + size cap.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from coba.utils.logging import get_logger
from coba.utils.schemas import Finding

log = get_logger("coba.agent.skip_cache")

_SCHEMA_VERSION = "skip-cache.v1"


@dataclass
class SkipCacheRecord:
    """One cache row keyed by SHA-256 of file bytes."""

    sha256: str
    file: str
    n_findings: int
    findings: list[dict[str, Any]] = field(default_factory=list)
    schema_version: str = _SCHEMA_VERSION

    def to_findings(self) -> list[Finding]:
        out: list[Finding] = []
        for row in self.findings:
            try:
                out.append(Finding.model_validate(row))
            except Exception as exc:  # pragma: no cover
                log.debug("skip_cache.bad_finding_row", error=str(exc))
        return out

    @classmethod
    def from_findings(cls, sha256: str, file: str, findings: list[Finding]) -> SkipCacheRecord:
        return cls(
            sha256=sha256,
            file=file,
            n_findings=len(findings),
            findings=[f.model_dump(mode="json") for f in findings],
        )


def hash_file(path: Path) -> str | None:
    """Return SHA-256 hex digest of the file bytes, or ``None`` on read error.

    We hash bytes (not text) so line-ending changes are surfaced. A
    silent ``None`` lets the caller fall back to a fresh scan instead of
    a hard error.
    """
    try:
        h = hashlib.sha256()
        with path.open("rb") as f:
            for block in iter(lambda: f.read(64 * 1024), b""):
                h.update(block)
        return h.hexdigest()
    except OSError as exc:
        log.debug("skip_cache.hash_failed", file=str(path), error=str(exc))
        return None


class SkipCache:
    """File-hash-keyed cache living under ``<cache_dir>/skip/``.

    The cache is keyed on file *content* hash — moving or renaming a
    file does not invalidate the entry, which is exactly what we want
    for incremental scans of the same codebase under different paths
    (CI runner workdirs change every build).
    """

    def __init__(self, cache_dir: Path, *, enabled: bool = True) -> None:
        self.root = Path(cache_dir) / "skip"
        self.enabled = enabled
        if self.enabled:
            self.root.mkdir(parents=True, exist_ok=True)
        self._hits = 0
        self._misses = 0
        self._writes = 0

    # ---------------------------------------------------------------- public
    def get(self, sha256: str) -> SkipCacheRecord | None:
        if not self.enabled or not sha256:
            return None
        path = self._path_for(sha256)
        if not path.exists():
            self._misses += 1
            return None
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            log.debug("skip_cache.read_failed", path=str(path), error=str(exc))
            self._misses += 1
            return None
        if data.get("schema_version") != _SCHEMA_VERSION:
            self._misses += 1
            return None
        self._hits += 1
        return SkipCacheRecord(
            sha256=data["sha256"],
            file=data.get("file", ""),
            n_findings=int(data.get("n_findings", 0)),
            findings=list(data.get("findings", [])),
        )

    def put(self, record: SkipCacheRecord) -> None:
        if not self.enabled or not record.sha256:
            return
        path = self._path_for(record.sha256)
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            tmp = path.with_suffix(".tmp")
            tmp.write_text(json.dumps(asdict(record), ensure_ascii=False), encoding="utf-8")
            tmp.replace(path)
            self._writes += 1
        except OSError as exc:  # pragma: no cover
            log.debug("skip_cache.write_failed", path=str(path), error=str(exc))

    def stats(self) -> dict[str, int]:
        return {"hits": self._hits, "misses": self._misses, "writes": self._writes}

    # --------------------------------------------------------------- helpers
    def _path_for(self, sha256: str) -> Path:
        # Shard by first 2 hex chars to keep directories small.
        return self.root / sha256[:2] / f"{sha256}.json"
