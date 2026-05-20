"""LLM Verifier — critiques each RawFinding to filter false positives."""

from __future__ import annotations

import json
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

from coba.llm.base import TaskKind
from coba.llm.router import LLMRouter
from coba.utils.logging import get_logger
from coba.utils.sanitize import sanitize_code_for_prompt
from coba.utils.schemas import Chunk, LLMMessage, RawFinding, Role, Verdict

log = get_logger("coba.agent.verifier")

PROMPTS_DIR = Path(__file__).resolve().parent.parent / "prompts"


class Verifier:
    """Reviews a Detector finding with expanded context and emits a verdict."""

    def __init__(self, router: LLMRouter) -> None:
        self.router = router
        self._env = Environment(
            loader=FileSystemLoader(str(PROMPTS_DIR)),
            autoescape=select_autoescape(disabled_extensions=("j2",)),
            keep_trailing_newline=True,
        )

    async def verify(
        self,
        chunk: Chunk,
        finding: RawFinding,
    ) -> tuple[Verdict, str]:
        template = self._env.get_template("verifier.j2")
        prompt = template.render(
            chunk=chunk,
            body=sanitize_code_for_prompt(chunk.body),
            finding=finding.model_dump(),
        )

        try:
            resp = await self.router.complete(
                TaskKind.VERIFIER,
                [
                    LLMMessage(role=Role.SYSTEM, content=_VERIFIER_SYSTEM),
                    LLMMessage(role=Role.USER, content=prompt),
                ],
                temperature=0.0,
                max_tokens=512,
                json_mode=True,
            )
        except Exception as exc:  # pragma: no cover
            log.warning("verifier.llm_failed", error=str(exc))
            return Verdict.UNVERIFIED, "verifier-llm-failed"

        return _parse_verdict(resp.text)


_VERIFIER_SYSTEM = (
    "You are a senior application-security triage reviewer. Given a finding "
    "claim and the code, decide whether it's a TRUE_POSITIVE or FALSE_POSITIVE. "
    "Re-derive the data flow yourself; if you cannot, return FALSE_POSITIVE. "
    "Respond with strict JSON: "
    '{"verdict":"TRUE_POSITIVE|FALSE_POSITIVE","confidence":0.0-1.0,'
    '"rationale":"..."}.'
)


def _parse_verdict(text: str) -> tuple[Verdict, str]:
    text = text.strip()
    if text.startswith("```"):
        text = text.split("```", 2)[1]
        if text.lower().startswith("json"):
            text = text[4:]
    text = text.strip()
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return Verdict.UNVERIFIED, "verifier-bad-json"
    verdict_raw = data.get("verdict", "FALSE_POSITIVE")
    rationale = data.get("rationale", "")
    try:
        verdict = Verdict(verdict_raw)
    except ValueError:
        verdict = Verdict.FALSE_POSITIVE
    return verdict, rationale
