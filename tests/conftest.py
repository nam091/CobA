"""Shared pytest fixtures and config."""

from __future__ import annotations

import asyncio
import os
import sys
from collections.abc import Generator
from pathlib import Path

import pytest

# Ensure src/ is on the path for editable installs in CI without `pip install -e`.
ROOT = Path(__file__).resolve().parent.parent
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

# Prevent CobA from picking up the developer's .env during tests.
os.environ.setdefault("COBA_LLM_DAILY_BUDGET_USD", "5.0")


@pytest.fixture()
def anyio_backend() -> str:
    return "asyncio"


@pytest.fixture()
def event_loop() -> Generator[asyncio.AbstractEventLoop, None, None]:
    loop = asyncio.new_event_loop()
    yield loop
    loop.close()
