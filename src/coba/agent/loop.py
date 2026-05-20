"""Orchestrator — coordinates the entire scan pipeline."""

from __future__ import annotations

import asyncio
import time
from datetime import UTC, datetime
from pathlib import Path

from coba.agent.detector import Detector
from coba.agent.planner import Planner
from coba.agent.rag import RagIndex
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
        self.rag = rag or RagIndex()
        self.detector = Detector(self.router, self.rag)
        self.verifier = Verifier(self.router)
        self.tools: list[SASTTool] = tools or [
            SemgrepRunner(),
            BanditRunner(),
            GitleaksRunner(),
            # Joern is heavy; include only when available.
            JoernRunner(),
        ]

    # ---------------------------------------------------------------- public
    async def scan(self, request: ScanRequest) -> ScanReport:
        if request.no_cloud:
            self.settings.coba_no_cloud = True

        target = self._resolve_target(request)
        report = ScanReport(target=str(target), started_at=datetime.now(UTC))
        stats = ScanStats()
        timings: dict[str, float] = {}

        # 1) Plan ----------------------------------------------------------
        t0 = time.perf_counter()
        planner = Planner(languages=request.languages or None)
        files, chunks = planner.plan(target)
        stats.n_files = len(files)
        stats.n_chunks = len(chunks)
        timings["plan"] = time.perf_counter() - t0

        # 2) Static pre-scan ----------------------------------------------
        t0 = time.perf_counter()
        static_hints_by_file = await self._run_static(target)
        stats.n_static_findings = sum(len(v) for v in static_hints_by_file.values())
        timings["static"] = time.perf_counter() - t0

        # 3) LLM Detector (parallel) --------------------------------------
        t0 = time.perf_counter()
        raw_pairs = await self._run_detector(chunks, static_hints_by_file)
        stats.n_raw_findings = sum(len(rs) for _, rs in raw_pairs)
        timings["detector"] = time.perf_counter() - t0

        # 4) Filter (schema/grounding) + Verifier -------------------------
        t0 = time.perf_counter()
        findings: list[Finding] = []
        for chunk, raws in raw_pairs:
            for raw in raws:
                if not self._grounding_filter(chunk, raw):
                    stats.n_schema_rejected += 1
                    continue
                verdict, rationale = await self.verifier.verify(chunk, raw)
                if verdict == Verdict.FALSE_POSITIVE:
                    stats.n_verifier_rejected += 1
                    continue
                findings.append(_to_final(chunk, raw, verdict, rationale))
        stats.n_final_findings = len(findings)
        timings["verifier"] = time.perf_counter() - t0

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

    async def _run_static(self, target: Path) -> dict[str, list[StaticHint]]:
        """Run each SAST tool and group hints by file."""

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
        # Group by file path (StaticHint doesn't carry file; tools encode in rule_id).
        # For v0 we keep a single "global" bucket since hints' file path is implicit
        # in the chunk. Future: extend StaticHint with a `file` field.
        return {"_global": flat}

    async def _run_detector(
        self, chunks: list[Chunk], hints_by_file: dict[str, list[StaticHint]]
    ) -> list[tuple[Chunk, list[RawFinding]]]:
        sem = asyncio.Semaphore(self.settings.coba_parallel_llm_calls)

        async def one(chunk: Chunk) -> tuple[Chunk, list[RawFinding]]:
            relevant = self._hints_for_chunk(chunk, hints_by_file)
            async with sem:
                raws = await self.detector.detect(chunk, relevant)
            return chunk, raws

        return await asyncio.gather(*(one(c) for c in chunks))

    @staticmethod
    def _hints_for_chunk(
        chunk: Chunk, hints_by_file: dict[str, list[StaticHint]]
    ) -> list[StaticHint]:
        # v0: just filter by line range against the global bucket.
        out: list[StaticHint] = []
        for h in hints_by_file.get("_global", []):
            if chunk.line_start <= h.line <= chunk.line_end:
                out.append(h)
        return out

    @staticmethod
    def _grounding_filter(chunk: Chunk, raw: RawFinding) -> bool:
        if raw.line_start > raw.line_end:
            return False
        if raw.line_end < chunk.line_start or raw.line_start > chunk.line_end:
            return False
        if not raw.cwe.startswith("CWE-"):
            return False
        return True


def _to_final(chunk: Chunk, raw: RawFinding, verdict: Verdict, rationale: str) -> Finding:
    return Finding(
        file=chunk.file,
        function=chunk.function,
        line_start=raw.line_start,
        line_end=raw.line_end,
        cwe=raw.cwe,
        severity=raw.severity
        if isinstance(raw.severity, Severity)
        else Severity.from_str(str(raw.severity)),
        confidence=raw.confidence,
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
