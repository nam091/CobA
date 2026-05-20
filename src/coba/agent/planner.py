"""Planner — discover files, prioritize, produce a list of Chunks."""

from __future__ import annotations

from pathlib import Path

from coba.agent.callgraph import CallGraph
from coba.agent.chunker import chunk_file
from coba.config.settings import get_settings
from coba.utils.logging import get_logger
from coba.utils.schemas import Chunk, Language, StaticHint


def _file_key(path: str) -> str:
    """Canonical absolute-path key used by ``prioritize``.

    Mirrors ``Orchestrator._normalize_file_key`` so the two stay in sync.
    """
    try:
        return str(Path(path).resolve())
    except OSError:
        return path


log = get_logger("coba.agent.planner")

# Common ignore patterns.
_IGNORE_DIRS = {
    ".git",
    ".hg",
    ".svn",
    "node_modules",
    "dist",
    "build",
    "target",
    "__pycache__",
    ".pytest_cache",
    ".mypy_cache",
    ".ruff_cache",
    "venv",
    ".venv",
    "env",
    ".coba_data",
    ".coba_cache",
}
_TEXT_EXTS = {
    ".py",
    ".java",
    ".c",
    ".cc",
    ".cpp",
    ".h",
    ".hpp",
    ".js",
    ".jsx",
    ".ts",
    ".tsx",
    ".mjs",
    ".cjs",
}


class Planner:
    """Walks a target tree, picks files in scope, and chunks them."""

    def __init__(self, languages: list[Language] | None = None) -> None:
        self.languages = languages
        self.settings = get_settings()

    def discover_files(self, target: Path) -> list[Path]:
        if target.is_file():
            return [target] if self._in_scope(target) else []
        files: list[Path] = []
        for root in target.rglob("*"):
            if root.is_dir():
                if root.name in _IGNORE_DIRS:
                    # rglob does not provide pruning; we skip by checking parents.
                    continue
                continue
            if any(part in _IGNORE_DIRS for part in root.parts):
                continue
            if not self._in_scope(root):
                continue
            try:
                if root.stat().st_size > self.settings.coba_max_file_size_kb * 1024:
                    continue
            except OSError:
                continue
            files.append(root)
        return files

    def _in_scope(self, p: Path) -> bool:
        if p.suffix.lower() not in _TEXT_EXTS:
            return False
        lang = Language.from_path(str(p))
        if lang == Language.UNKNOWN:
            return False
        if self.languages and lang not in self.languages:
            return False
        return True

    def chunk_files(self, files: list[Path], *, call_graph: CallGraph | None = None) -> list[Chunk]:
        all_chunks: list[Chunk] = []
        for f in files:
            try:
                all_chunks.extend(chunk_file(f, call_graph=call_graph))
            except Exception as exc:  # pragma: no cover
                log.warning("planner.chunk_failed", file=str(f), error=str(exc))
        return all_chunks

    @staticmethod
    def prioritize(chunks: list[Chunk], hints_by_file: dict[str, list[StaticHint]]) -> list[Chunk]:
        """Return ``chunks`` ordered so that those overlapping static-tool hints
        come first; ties broken by hint count (descending), then by file then
        line for determinism.

        ``hints_by_file`` is the canonicalised map produced by
        ``Orchestrator._group_hints_by_file``. Keys are absolute paths (plus
        the ``"_global"`` bucket for hints without a file). We score each
        chunk by the number of *matching* hints — those whose line range is
        inside ``[chunk.line_start, chunk.line_end]``.
        """
        if not hints_by_file:
            return list(chunks)

        def score(chunk: Chunk) -> int:
            # Try exact match first, then ``_global`` bucket as fallback.
            key = _file_key(chunk.file)
            candidates = hints_by_file.get(key, []) + hints_by_file.get("_global", [])
            return sum(1 for h in candidates if chunk.line_start <= h.line <= chunk.line_end)

        # Stable sort: chunks with more hints first, then alpha by file/line.
        return sorted(
            chunks,
            key=lambda c: (-score(c), c.file, c.line_start),
        )

    def plan(
        self, target: Path, *, call_graph: CallGraph | None = None
    ) -> tuple[list[Path], list[Chunk]]:
        files = self.discover_files(target)
        chunks = self.chunk_files(files, call_graph=call_graph)
        log.info(
            "planner.done",
            n_files=len(files),
            n_chunks=len(chunks),
            cg_enriched=call_graph.n_functions if call_graph else 0,
        )
        return files, chunks
