"""Semgrep wrapper."""

from __future__ import annotations

import json
from pathlib import Path

from coba.config.settings import get_settings
from coba.tools.base import SASTTool, ToolNotInstalled
from coba.utils.logging import get_logger
from coba.utils.schemas import Severity, StaticHint

log = get_logger("coba.tools.semgrep")


class SemgrepRunner(SASTTool):
    name = "semgrep"
    languages = ["python", "java", "c", "cpp", "javascript", "typescript", "go"]

    DEFAULT_CONFIGS = [
        "p/security-audit",
        "p/owasp-top-ten",
        "p/cwe-top-25",
    ]

    def __init__(self, configs: list[str] | None = None) -> None:
        s = get_settings()
        self.binary = s.semgrep_bin
        self.configs = configs or self.DEFAULT_CONFIGS

    async def run(self, target: Path) -> list[StaticHint]:
        if not self.installed():
            raise ToolNotInstalled(f"`{self.binary}` not found on PATH")

        cmd = [self.binary]
        for cfg in self.configs:
            cmd.extend(["--config", cfg])
        cmd.extend(
            [
                "--json",
                "--quiet",
                "--timeout",
                "60",
                "--max-target-bytes",
                "1000000",
                str(target),
            ]
        )
        rc, stdout, stderr = await self._run_subprocess(cmd, timeout=600.0)
        if rc not in (0, 1):  # semgrep exits 1 when findings exist
            log.warning("semgrep.rc", rc=rc, stderr=stderr[:500].decode(errors="ignore"))
            return []
        try:
            data = json.loads(stdout or b"{}")
        except json.JSONDecodeError:
            log.warning("semgrep.parse_failed")
            return []
        return [self._to_hint(result) for result in data.get("results", []) if "path" in result]

    @staticmethod
    def _to_hint(r: dict) -> StaticHint:
        extra = r.get("extra", {}) or {}
        metadata = extra.get("metadata", {}) or {}
        cwe = None
        cwe_md = metadata.get("cwe") or metadata.get("cwe-id")
        if cwe_md:
            # Could be a list or string like "CWE-89: SQL injection"
            cwe_str = cwe_md[0] if isinstance(cwe_md, list) else cwe_md
            cwe = cwe_str.split(":")[0].strip().upper()
            if not cwe.startswith("CWE-"):
                cwe = f"CWE-{cwe}"
        severity = Severity.from_str(extra.get("severity", "MEDIUM"))
        return StaticHint(
            tool="semgrep",
            rule_id=r.get("check_id", "unknown"),
            line=int(r.get("start", {}).get("line", 0)),
            message=extra.get("message", "")[:500],
            cwe=cwe,
            severity=severity,
        )
