"""Orchestrator — coordinates the entire scan pipeline."""

from __future__ import annotations

import asyncio
import contextlib
import time
from datetime import UTC, datetime
from pathlib import Path

from coba.agent.callgraph import EMPTY_CALL_GRAPH, CallGraph
from coba.agent.detector import Detector
from coba.agent.planner import Planner
from coba.agent.rag import RagIndex, load_rag_index
from coba.agent.skip_cache import SkipCache, SkipCacheRecord, hash_file
from coba.agent.verifier import Verifier
from coba.config.settings import get_settings
from coba.llm.router import LLMRouter
from coba.tools import BanditRunner, GitleaksRunner, JoernRunner, SemgrepRunner
from coba.tools.base import SASTTool, ToolNotInstalled
from coba.utils.logging import get_logger
from coba.utils.schemas import (
    Chunk,
    Finding,
    Language,
    RawFinding,
    ScanReport,
    ScanRequest,
    ScanStats,
    Severity,
    StaticHint,
    Verdict,
)

log = get_logger("coba.agent.loop")


class Orchestrator:
    """Top-level scan pipeline."""

    def __init__(
        self,
        router: LLMRouter | None = None,
        rag: RagIndex | None = None,
        tools: list[SASTTool] | None = None,
    ) -> None:
        self.settings = get_settings()
        self.router = router or LLMRouter(self.settings)
        self.rag = rag or load_rag_index()
        self.detector = Detector(self.router, self.rag)
        self.verifier = Verifier(self.router)
        self.tools: list[SASTTool] = tools or [
            SemgrepRunner(),
            BanditRunner(),
            GitleaksRunner(),
            # Joern is heavy; include only when available.
            JoernRunner(),
        ]
        self.skip_cache = SkipCache(
            self.settings.cache_dir,
            enabled=self.settings.coba_skip_cache_enabled,
        )

    # ---------------------------------------------------------------- public
    async def scan(self, request: ScanRequest) -> ScanReport:
        if request.no_cloud:
            self.settings.coba_no_cloud = True

        target = self._resolve_target(request)
        report = ScanReport(target=str(target), started_at=datetime.now(UTC))
        stats = ScanStats()
        timings: dict[str, float] = {}

        # 0) (Optional) Build a Joern call graph for CPG-aware context.
        #    Always safe: returns EMPTY_CALL_GRAPH if Joern is not available.
        t0 = time.perf_counter()
        call_graph = await self._build_call_graph(target)
        timings["callgraph"] = time.perf_counter() - t0

        # 1) Plan ----------------------------------------------------------
        t0 = time.perf_counter()
        planner = Planner(languages=request.languages or None)
        files, chunks = planner.plan(target, call_graph=call_graph)
        stats.n_files = len(files)
        stats.n_chunks = len(chunks)
        timings["plan"] = time.perf_counter() - t0

        # 2) Static pre-scan ----------------------------------------------
        t0 = time.perf_counter()
        static_hints_by_file = await self._run_static(target)
        stats.n_static_findings = sum(len(v) for v in static_hints_by_file.values())
        timings["static"] = time.perf_counter() - t0

        # 2.5) Skip-cache: short-circuit files whose content has not changed.
        t0 = time.perf_counter()
        cached_findings, chunks_to_scan, file_hashes = self._apply_skip_cache(files, chunks)
        stats.n_chunks_cache_hit = len(chunks) - len(chunks_to_scan)
        timings["skip_cache"] = time.perf_counter() - t0

        # 2.6) Priority queue — hot chunks (with static hints) first.
        chunks_to_scan = Planner.prioritize(chunks_to_scan, static_hints_by_file)

        # 3) LLM Detector (parallel, budget-capped) ------------------------
        t0 = time.perf_counter()
        raw_pairs, n_budget_skipped = await self._run_detector(chunks_to_scan, static_hints_by_file)
        stats.n_raw_findings = sum(len(rs) for _, rs in raw_pairs)
        stats.n_chunks_budget_skipped = n_budget_skipped
        timings["detector"] = time.perf_counter() - t0

        # 4) Filter (schema/grounding) + Verifier -------------------------
        t0 = time.perf_counter()
        findings: list[Finding] = []
        for chunk, raws in raw_pairs:
            for raw in raws:
                if not self._grounding_filter(chunk, raw):
                    stats.n_schema_rejected += 1
                    continue
                v = await self.verifier.verify_detailed(chunk, raw)
                if v.verdict == Verdict.FALSE_POSITIVE:
                    stats.n_verifier_rejected += 1
                    continue
                findings.append(_to_final(chunk, raw, v.verdict, v.rationale, v.confidence))
        # Merge cached findings back in for the final report.
        findings.extend(cached_findings)
        stats.n_final_findings = len(findings)
        timings["verifier"] = time.perf_counter() - t0

        # 4.5) Persist freshly scanned files into the skip cache.
        self._persist_skip_cache(findings, chunks_to_scan, file_hashes, cached_findings)

        # 5) Cost + finalize ----------------------------------------------
        stats.total_cost_usd = self.router.cost.spent
        stats.timings = timings
        report.findings = findings
        report.finished_at = datetime.now(UTC)
        report.duration_seconds = (report.finished_at - report.started_at).total_seconds()
        report.stats = stats
        log.info(
            "orchestrator.done",
            target=str(target),
            n_files=stats.n_files,
            n_chunks=stats.n_chunks,
            n_findings=stats.n_final_findings,
            cost_usd=round(stats.total_cost_usd, 4),
            duration_s=round(report.duration_seconds or 0, 2),
        )
        return report

    # --------------------------------------------------------------- helpers
    def _resolve_target(self, request: ScanRequest) -> Path:
        if request.target_path:
            return Path(request.target_path).resolve()
        if request.git_url:
            raise NotImplementedError("git clone path not implemented in v0")
        raise ValueError("ScanRequest must provide target_path or git_url")

    async def _build_call_graph(self, target: Path) -> CallGraph:
        """Best-effort: extract a call graph via Joern. Falls back to empty.

        Joern is the only tool currently capable of producing a usable call
        graph for all four supported languages. We skip the step (returning
        :data:`EMPTY_CALL_GRAPH`) when:

        * Joern is not installed on this machine;
        * the CPG build fails or times out;
        * the call-graph script produces non-JSON output.

        See ``src/coba/tools/joern_queries/call_graph.sc``.
        """
        joern: JoernRunner | None = next(
            (t for t in self.tools if isinstance(t, JoernRunner)), None
        )
        if joern is None:
            return EMPTY_CALL_GRAPH
        try:
            return await joern.extract_call_graph(target)
        except Exception as exc:  # pragma: no cover - defensive
            log.warning("orchestrator.callgraph_failed", error=str(exc))
            return EMPTY_CALL_GRAPH

    async def _run_static(self, target: Path) -> dict[str, list[StaticHint]]:
        """Run each SAST tool and group hints by file (with a global bucket for hints
        whose file path could not be resolved)."""

        async def run_one(tool: SASTTool) -> list[StaticHint]:
            try:
                if not tool.installed():
                    log.info("orchestrator.tool_missing", tool=tool.name)
                    return []
                return await tool.run(target)
            except ToolNotInstalled:
                return []
            except Exception as exc:  # pragma: no cover
                log.warning("orchestrator.tool_failed", tool=tool.name, error=str(exc))
                return []

        results = await asyncio.gather(*(run_one(t) for t in self.tools))
        flat: list[StaticHint] = [h for hs in results for h in hs]
        return _group_hints_by_file(flat, target)

    async def _run_detector(
        self, chunks: list[Chunk], hints_by_file: dict[str, list[StaticHint]]
    ) -> tuple[list[tuple[Chunk, list[RawFinding]]], int]:
        """Run the Detector over ``chunks`` honouring the per-scan budget cap.

        Returns the per-chunk raw findings plus the number of chunks that
        were skipped because the budget was exhausted. The budget is
        polled before kicking off each LLM call so we never *start* a
        request we cannot afford.
        """
        sem = asyncio.Semaphore(self.settings.coba_parallel_llm_calls)
        budget = self.settings.coba_scan_budget_usd
        budget_exhausted = False
        skipped = 0
        results: list[tuple[Chunk, list[RawFinding]]] = []

        async def one(chunk: Chunk) -> tuple[Chunk, list[RawFinding]]:
            relevant = self._hints_for_chunk(chunk, hints_by_file)
            async with sem:
                raws = await self.detector.detect(chunk, relevant)
            return chunk, raws

        for chunk in chunks:
            if budget > 0 and self.router.cost.spent >= budget:
                if not budget_exhausted:
                    log.warning(
                        "orchestrator.budget_exhausted",
                        spent_usd=round(self.router.cost.spent, 4),
                        budget_usd=budget,
                    )
                    budget_exhausted = True
                skipped += 1
                continue
            results.append(await one(chunk))
        return results, skipped

    def _apply_skip_cache(
        self,
        files: list[Path],
        chunks: list[Chunk],
    ) -> tuple[list[Finding], list[Chunk], dict[str, str]]:
        """Partition chunks into "cached" (skip) vs "to scan".

        Returns ``(cached_findings, chunks_to_scan, file_hashes)``:
        - ``cached_findings``: findings reused from previous scans.
        - ``chunks_to_scan``: chunks whose owning file is *not* in the
          cache; these will go through Detector + Verifier.
        - ``file_hashes``: map from canonical file path -> sha256, so the
          caller can persist new results after the scan.
        """
        cached_findings: list[Finding] = []
        chunks_to_scan: list[Chunk] = []
        file_hashes: dict[str, str] = {}
        cached_files: set[str] = set()

        for f in files:
            sha = hash_file(f)
            key = _normalize_file_key(str(f))
            if sha is None:
                continue
            file_hashes[key] = sha
            rec = self.skip_cache.get(sha)
            if rec is None:
                continue
            cached_findings.extend(rec.to_findings())
            cached_files.add(key)

        for ch in chunks:
            if _normalize_file_key(ch.file) in cached_files:
                continue
            chunks_to_scan.append(ch)
        return cached_findings, chunks_to_scan, file_hashes

    def _persist_skip_cache(
        self,
        all_findings: list[Finding],
        chunks_scanned: list[Chunk],
        file_hashes: dict[str, str],
        cached_findings: list[Finding],
    ) -> None:
        """Write per-file findings for every freshly scanned file into the cache.

        Cache hits are written through unchanged so the entry stays alive
        for files where Detector returned zero findings (clean files
        must still be cacheable — otherwise they re-scan every time).
        """
        if not self.skip_cache.enabled:
            return
        scanned_files = {_normalize_file_key(c.file) for c in chunks_scanned}
        # Index findings (excluding the ones we just restored from cache)
        # by canonical file path so we only re-write fresh content.
        cached_id = {(f.file, f.line_start, f.cwe) for f in cached_findings}
        per_file: dict[str, list[Finding]] = {k: [] for k in scanned_files}
        for f in all_findings:
            if (f.file, f.line_start, f.cwe) in cached_id:
                continue
            key = _normalize_file_key(f.file)
            if key in per_file:
                per_file[key].append(f)
        for key, findings in per_file.items():
            sha = file_hashes.get(key)
            if not sha:
                continue
            self.skip_cache.put(SkipCacheRecord.from_findings(sha, key, findings))

    @staticmethod
    def _hints_for_chunk(
        chunk: Chunk, hints_by_file: dict[str, list[StaticHint]]
    ) -> list[StaticHint]:
        """Return hints whose file matches ``chunk.file`` and whose line falls
        inside the chunk's line range. Hints in the ``_global`` bucket are
        line-range-matched only (tool reported no file)."""
        chunk_key = _normalize_file_key(chunk.file)
        candidates = list(hints_by_file.get(chunk_key, []))
        candidates.extend(hints_by_file.get("_global", []))
        return [h for h in candidates if chunk.line_start <= h.line <= chunk.line_end]

    @staticmethod
    def _grounding_filter(chunk: Chunk, raw: RawFinding) -> bool:
        if raw.line_start > raw.line_end:
            return False
        if raw.line_end < chunk.line_start or raw.line_start > chunk.line_end:
            return False
        if not raw.cwe.startswith("CWE-"):
            return False
        return True


def _normalize_file_key(path: str) -> str:
    """Best-effort canonical key for grouping/looking-up hints by file path.

    Tools report file paths in slightly different forms (absolute / relative
    to scan target / with ``./`` prefix). We canonicalize to an absolute path
    string when possible and fall back to the input.
    """
    try:
        return str(Path(path).resolve())
    except OSError:
        return path


def _group_hints_by_file(hints: list[StaticHint], target: Path) -> dict[str, list[StaticHint]]:
    """Group static hints into buckets keyed by canonical file path.

    Hints missing a ``file`` attribute land in a ``"_global"`` bucket so the
    orchestrator can still match them by line range as a fallback. Relative
    paths are resolved against ``target``.
    """
    grouped: dict[str, list[StaticHint]] = {"_global": []}
    target_root = target if target.is_dir() else target.parent
    for h in hints:
        if not h.file:
            grouped["_global"].append(h)
            continue
        p = Path(h.file)
        if not p.is_absolute():
            p = (target_root / p).resolve()
        else:
            with contextlib.suppress(OSError):
                p = p.resolve()
        grouped.setdefault(str(p), []).append(h)
    return grouped


def _to_final(
    chunk: Chunk,
    raw: RawFinding,
    verdict: Verdict,
    rationale: str,
    verifier_confidence: float = 0.0,
) -> Finding:
    blended = (
        max(0.0, min(1.0, raw.confidence * 0.4 + verifier_confidence * 0.6))
        if verifier_confidence > 0
        else raw.confidence
    )
    return Finding(
        file=chunk.file,
        function=chunk.function,
        line_start=raw.line_start,
        line_end=raw.line_end,
        cwe=raw.cwe,
        severity=raw.severity
        if isinstance(raw.severity, Severity)
        else Severity.from_str(str(raw.severity)),
        confidence=blended,
        title=raw.title,
        description=raw.description,
        data_flow=raw.data_flow,
        fix_suggestion=raw.fix_suggestion,
        sources=["llm-detector"],
        verifier_verdict=verdict,
        verifier_rationale=rationale or None,
    )


# Mark unused imports as used so static analyzers don't strip them.
_ = Language
