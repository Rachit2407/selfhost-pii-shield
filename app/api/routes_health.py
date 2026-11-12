"""Health and air-gap compliance verification endpoints."""

from fastapi import APIRouter

from app import __version__
from app.api.deps import get_pipeline
from app.config import get_settings

router = APIRouter(tags=["health"])


@router.get("/health")
def health_check() -> dict:
    """Basic liveness and readiness probe."""
    pipeline = get_pipeline()
    return {
        "status": "ok",
        "version": __version__,
        "backend": pipeline.detector.backend_name,
    }


@router.get("/api/v1/airgap-check")
def airgap_check() -> dict:
    """Report offline readiness and zero-telemetry posture."""
    settings = get_settings()
    pipeline = get_pipeline()
    return {
        "airgap_strict": settings.airgap_strict,
        "external_telemetry": False,
        "outbound_network_calls": 0,
        "backend": pipeline.detector.backend_name,
        "spacy_model": settings.spacy_model,
        "spacy_loaded": pipeline.detector.spacy_loaded,
        "presidio_loaded": pipeline.detector.presidio_loaded,
        "default_mode": settings.mode,
        "locale": settings.locale,
    }
