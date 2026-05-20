"""Abstract base class for SAST tool wrappers."""

from __future__ import annotations

import asyncio
import shutil
from abc import ABC, abstractmethod
from pathlib import Path

from coba.utils.logging import get_logger
from coba.utils.schemas import StaticHint

log = get_logger("coba.tools")


class ToolNotInstalled(RuntimeError):
    """Raised when the underlying tool binary is missing on PATH."""


class SASTTool(ABC):
    """A SAST tool wrapped to produce normalized ``StaticHint`` objects."""

    name: str = "abstract"
    languages: list[str] = []
    binary: str = ""

    def installed(self) -> bool:
        return shutil.which(self.binary) is not None

    async def _run_subprocess(
        self, cmd: list[str], *, timeout: float = 120.0, cwd: Path | None = None
    ) -> tuple[int, bytes, bytes]:
        log.debug("tool.subprocess", tool=self.name, cmd=" ".join(cmd))
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            cwd=str(cwd) if cwd else None,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
            return proc.returncode or 0, stdout, stderr
        except TimeoutError:
            proc.kill()
            log.warning("tool.timeout", tool=self.name, timeout=timeout)
            return -1, b"", b"timeout"

    @abstractmethod
    async def run(self, target: Path) -> list[StaticHint]:
        """Run the tool on ``target`` and return normalized hints."""
