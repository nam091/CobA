"""LLM Detector — runs the detector prompt on each chunk."""

from __future__ import annotations

import json
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape
from pydantic import ValidationError

from coba.agent.rag import RagIndex, RagSnippet
from coba.llm.base import TaskKind
from coba.llm.router import LLMRouter
from coba.utils.logging import get_logger
from coba.utils.sanitize import sanitize_code_for_prompt
from coba.utils.schemas import Chunk, LLMMessage, RawFinding, Role, StaticHint

log = get_logger("coba.agent.detector")

PROMPTS_DIR = Path(__file__).resolve().parent.parent / "prompts"


class Detector:
    """Run an LLM completion to extract RawFindings from a chunk."""

    def __init__(self, router: LLMRouter, rag: RagIndex | None = None) -> None:
        self.router = router
        self.rag = rag or RagIndex()
        self._env = Environment(
            loader=FileSystemLoader(str(PROMPTS_DIR)),
            autoescape=select_autoescape(disabled_extensions=("j2",)),
            keep_trailing_newline=True,
        )

    def _render_prompt(
        self, chunk: Chunk, hints: list[StaticHint], cwe_ctx: list[RagSnippet]
    ) -> str:
        template = self._env.get_template("detector.j2")
        return template.render(
            chunk=chunk,
            body=sanitize_code_for_prompt(chunk.body),
            static_hints=hints,
            cwe_context=cwe_ctx,
        )

    async def detect(self, chunk: Chunk, hints: list[StaticHint] | None = None) -> list[RawFinding]:
        hints = hints or []
        # Pull RAG context based on either the language/severity blocked by hints,
        # or just return the top CWEs for general guidance.
        cwe_keys = [h.cwe for h in hints if h.cwe]
        cwe_ctx = [self.rag.by_cwe(k) for k in cwe_keys if self.rag.by_cwe(k)] or self.rag.query(
            hints=[h.message for h in hints], top_k=3
        )
        prompt = self._render_prompt(chunk, hints, [c for c in cwe_ctx if c])

        try:
            resp = await self.router.complete(
                TaskKind.DETECTOR,
                [
                    LLMMessage(role=Role.SYSTEM, content=_DETECTOR_SYSTEM),
                    LLMMessage(role=Role.USER, content=prompt),
                ],
                temperature=0.0,
                max_tokens=1024,
                json_mode=True,
            )
        except Exception as exc:  # pragma: no cover
            log.warning("detector.llm_failed", error=str(exc), file=chunk.file)
            return []

        return _parse_findings(resp.text)


_DETECTOR_SYSTEM = (
    "You are a senior application-security engineer. You audit source code "
    "chunks for vulnerabilities. You MUST respond with strict JSON matching the "
    'schema {"findings": [...]}. Cite line ranges that exist in the chunk. '
    'Do NOT invent CWE ids. If nothing found, return {"findings": []}.'
)


def _parse_findings(text: str) -> list[RawFinding]:
    text = text.strip()
    # Models occasionally wrap JSON in ```json fences; strip them.
    if text.startswith("```"):
        text = text.split("```", 2)[1]
        if text.lower().startswith("json"):
            text = text[4:]
    text = text.strip()
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        log.warning("detector.invalid_json", text_preview=text[:200])
        return []
    items = data.get("findings", data) if isinstance(data, dict) else data
    if not isinstance(items, list):
        return []
    out: list[RawFinding] = []
    for raw in items:
        try:
            out.append(RawFinding.model_validate(raw))
        except ValidationError as exc:
            log.debug("detector.validation_failed", error=str(exc), raw=raw)
    return out
