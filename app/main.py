"""FastAPI entrypoint for Self-Hosted PII Shield (100% air-gapped local runtime)."""

from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from app import __version__
from app.api.deps import get_pipeline
from app.api.routes_db import router as db_router
from app.api.routes_health import router as health_router
from app.api.routes_scrub import router as scrub_router

STATIC_DIR = Path(__file__).resolve().parent / "static"


@asynccontextmanager
async def lifespan(_app: FastAPI):
    """Preload local NLP/Presidio models once at container startup."""
    get_pipeline()
    yield


def create_app() -> FastAPI:
    """Construct the FastAPI application with local-only routes and static UI."""
    application = FastAPI(
        title="Self-Hosted PII Shield",
        description="100% air-gapped PII redactor & deterministic synthetic DB anonymizer.",
        version=__version__,
        lifespan=lifespan,
    )
    application.include_router(health_router)
    application.include_router(scrub_router)
    application.include_router(db_router)

    if STATIC_DIR.exists():
        application.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

        @application.get("/", include_in_schema=False)
        def serve_ui() -> FileResponse:
            return FileResponse(STATIC_DIR / "index.html")

    return application


app = create_app()
