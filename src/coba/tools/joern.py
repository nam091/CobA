"""Joern wrapper — CPG build + simple taint queries.

This is a thin wrapper. Heavy queries live in
``src/coba/tools/joern_queries/*.sc`` (Scala scripts that ``joern --script``
can run). The wrapper is best-effort: if Joern is not installed or the CPG
build fails on a given repo, we log a warning and fall back to other tools.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from coba.config.settings import get_settings
from coba.tools.base import SASTTool, ToolNotInstalled
from coba.utils.logging import get_logger
from coba.utils.schemas import Severity, StaticHint

log = get_logger("coba.tools.joern")


class JoernRunner(SASTTool):
    name = "joern"
    languages = ["python", "java", "c", "cpp", "javascript"]

    def __init__(self) -> None:
        s = get_settings()
        self.binary = s.joern_bin
        self.parse_binary = s.joern_parse_bin
        self.cache_dir = s.cache_dir / "joern"
        self.cache_dir.mkdir(parents=True, exist_ok=True)

    def installed(self) -> bool:
        import shutil

        return shutil.which(self.binary) is not None and shutil.which(self.parse_binary) is not None

    @staticmethod
    def _hash_target(target: Path) -> str:
        h = hashlib.sha256()
        if target.is_file():
            h.update(target.read_bytes())
        else:
            for p in sorted(target.rglob("*")):
                if p.is_file():
                    try:
                        h.update(p.read_bytes())
                    except OSError:
                        continue
        return h.hexdigest()[:16]

    def cpg_path(self, target: Path) -> Path:
        return self.cache_dir / f"{self._hash_target(target)}.cpg.bin"

    async def build_cpg(self, target: Path) -> Path | None:
        """Build a CPG (cached) for ``target``. Returns the cpg path or None on failure."""
        if not self.installed():
            log.warning("joern.not_installed")
            return None
        out = self.cpg_path(target)
        if out.exists():
            log.info("joern.cache_hit", cpg=str(out))
            return out
        cmd = [self.parse_binary, str(target), "--output", str(out)]
        rc, stdout, stderr = await self._run_subprocess(cmd, timeout=600.0)
        if rc != 0 or not out.exists():
            log.warning("joern.parse_failed", rc=rc, stderr=stderr[:300].decode(errors="ignore"))
            return None
        return out

    async def run(self, target: Path) -> list[StaticHint]:
        """Run a small built-in taint query and return findings as hints.

        For now we only run a generic "exec-of-tainted-string" query that's
        valuable across languages. More queries can be added in ``joern_queries/``.
        """
        if not self.installed():
            raise ToolNotInstalled("joern / joern-parse missing on PATH")
        cpg = await self.build_cpg(target)
        if cpg is None:
            return []

        query_script = Path(__file__).parent / "joern_queries" / "exec_of_tainted_string.sc"
        if not query_script.exists():
            # Inline minimal query if the file isn't present yet.
            return []

        rc, stdout, _ = await self._run_subprocess(
            [self.binary, "--script", str(query_script), "--param", f"cpg={cpg}"],
            timeout=300.0,
        )
        if rc != 0:
            return []
        try:
            data = json.loads(stdout.decode("utf-8", errors="ignore") or "[]")
        except json.JSONDecodeError:
            return []
        return [
            StaticHint(
                tool="joern",
                rule_id="taint:exec_of_string",
                file=r.get("file"),
                line=int(r.get("line", 0)),
                message=r.get("message", "Tainted data reaches exec-like sink"),
                cwe="CWE-78",
                severity=Severity.HIGH,
            )
            for r in (data if isinstance(data, list) else [])
        ]
