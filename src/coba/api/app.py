"""FastAPI application factory."""

from __future__ import annotations

from fastapi import FastAPI

from coba import __version__
from coba.api.routes import router as scan_router
from coba.config.settings import get_settings
from coba.utils.logging import configure_logging


def create_app() -> FastAPI:
    settings = get_settings()
    configure_logging(level=settings.coba_log_level)
    app = FastAPI(
        title="CobA",
        description="LLM-powered Source Code Vulnerability Analysis Agent",
        version=__version__,
    )
    app.include_router(scan_router)
    return app


app = create_app()
