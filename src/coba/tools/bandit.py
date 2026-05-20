"""Bandit wrapper — Python-only SAST."""

from __future__ import annotations

import json
from pathlib import Path

from coba.config.settings import get_settings
from coba.tools.base import SASTTool, ToolNotInstalled
from coba.utils.logging import get_logger
from coba.utils.schemas import Severity, StaticHint

log = get_logger("coba.tools.bandit")


class BanditRunner(SASTTool):
    name = "bandit"
    languages = ["python"]

    def __init__(self) -> None:
        self.binary = get_settings().bandit_bin

    async def run(self, target: Path) -> list[StaticHint]:
        if not self.installed():
            raise ToolNotInstalled(f"`{self.binary}` not found on PATH")
        cmd = [
            self.binary,
            "-r",
            str(target),
            "-f",
            "json",
            "--severity-level",
            "low",
            "--skip",
            "B101",  # assert_used (noise in test files)
        ]
        rc, stdout, stderr = await self._run_subprocess(cmd, timeout=300.0)
        if rc not in (0, 1):
            log.warning("bandit.rc", rc=rc, stderr=stderr[:500].decode(errors="ignore"))
            return []
        try:
            data = json.loads(stdout or b"{}")
        except json.JSONDecodeError:
            return []
        return [self._to_hint(r) for r in data.get("results", [])]

    @staticmethod
    def _to_hint(r: dict) -> StaticHint:
        cwe = None
        issue_cwe = r.get("issue_cwe") or {}
        if isinstance(issue_cwe, dict):
            cwe_id = issue_cwe.get("id")
            if cwe_id:
                cwe = f"CWE-{cwe_id}"
        return StaticHint(
            tool="bandit",
            rule_id=r.get("test_id", "B000"),
            line=int(r.get("line_number", 0)),
            message=r.get("issue_text", "")[:500],
            cwe=cwe,
            severity=Severity.from_str(r.get("issue_severity")),
        )
