"""HTTP routes for /scan, /health, /models, /tools."""

from __future__ import annotations

import shutil
from typing import Annotated, Any

from fastapi import APIRouter, Body, HTTPException

from coba.agent.loop import Orchestrator
from coba.config.settings import get_settings
from coba.llm.cost import MODEL_PRICES
from coba.tools import BanditRunner, GitleaksRunner, JoernRunner, SemgrepRunner
from coba.utils.schemas import ScanReport, ScanRequest

router = APIRouter()


@router.get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok"}


@router.get("/models")
async def list_models() -> dict[str, Any]:
    s = get_settings()
    items = [
        {
            "model": m,
            "input_per_million_usd": p.input_per_million,
            "output_per_million_usd": p.output_per_million,
        }
        for m, p in MODEL_PRICES.items()
    ]
    return {
        "configured": {
            "detector": s.coba_llm_detector,
            "verifier": s.coba_llm_verifier,
            "offline_fallback": s.coba_llm_offline_fallback,
        },
        "models": items,
    }


@router.get("/tools")
async def list_tools() -> dict[str, Any]:
    tools = [SemgrepRunner(), BanditRunner(), GitleaksRunner(), JoernRunner()]
    return {
        "tools": [
            {
                "name": t.name,
                "binary": t.binary,
                "installed": bool(shutil.which(t.binary)),
                "languages": t.languages,
            }
            for t in tools
        ]
    }


@router.post("/scan", response_model=ScanReport)
async def scan(req: Annotated[ScanRequest, Body()]) -> ScanReport:
    if not req.target_path and not req.git_url:
        raise HTTPException(400, detail="Either target_path or git_url is required.")
    orch = Orchestrator()
    return await orch.scan(req)
