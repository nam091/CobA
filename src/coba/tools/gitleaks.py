"""Gitleaks wrapper — secret detection (CWE-798)."""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

from coba.config.settings import get_settings
from coba.tools.base import SASTTool, ToolNotInstalled
from coba.utils.logging import get_logger
from coba.utils.schemas import Severity, StaticHint

log = get_logger("coba.tools.gitleaks")


class GitleaksRunner(SASTTool):
    name = "gitleaks"
    languages = ["python", "java", "c", "cpp", "javascript", "typescript", "go", "any"]

    def __init__(self) -> None:
        self.binary = get_settings().gitleaks_bin

    async def run(self, target: Path) -> list[StaticHint]:
        if not self.installed():
            raise ToolNotInstalled(f"`{self.binary}` not found on PATH")

        with tempfile.NamedTemporaryFile("r", suffix=".json", delete=False) as fp:
            report = Path(fp.name)
        cmd = [
            self.binary,
            "detect",
            "--source",
            str(target),
            "--report-format",
            "json",
            "--report-path",
            str(report),
            "--no-banner",
            "--redact",
            "--exit-code",
            "0",
        ]
        rc, stdout, stderr = await self._run_subprocess(cmd, timeout=300.0)
        if not report.exists():
            log.warning("gitleaks.no_report", rc=rc, stderr=stderr[:300].decode(errors="ignore"))
            return []
        try:
            data = json.loads(report.read_text() or "[]")
        except json.JSONDecodeError:
            return []
        finally:
            report.unlink(missing_ok=True)
        return [self._to_hint(r) for r in data]

    @staticmethod
    def _to_hint(r: dict) -> StaticHint:
        return StaticHint(
            tool="gitleaks",
            rule_id=r.get("RuleID", "unknown"),
            line=int(r.get("StartLine", 0)),
            message=f"Hard-coded secret detected: {r.get('Description', '')}"[:500],
            cwe="CWE-798",
            severity=Severity.HIGH,
        )
