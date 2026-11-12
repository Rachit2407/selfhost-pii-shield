"""Shared singleton dependency builder for the offline PII pipeline."""

from functools import lru_cache
from pathlib import Path

from app.config import get_settings
from app.engine.deterministic import DeterministicAnonymizer
from app.engine.detector import LocalPIIDetector
from app.engine.pipeline import PIIShieldPipeline
from app.enterprise.hooks import AuditSink, AuthProvider, LocalJsonlAuditSink, OpenCoreAuthProvider


@lru_cache(maxsize=1)
def get_pipeline() -> PIIShieldPipeline:
    """Build and cache the offline detector + deterministic anonymizer pipeline."""
    settings = get_settings()
    detector = LocalPIIDetector(
        spacy_model=settings.spacy_model,
        score_threshold=settings.score_threshold,
        airgap_strict=settings.airgap_strict,
    )
    anonymizer = DeterministicAnonymizer(
        salt=settings.salt,
        locale=settings.locale,
    )
    return PIIShieldPipeline(
        detector=detector,
        anonymizer=anonymizer,
        default_mode=settings.mode,
    )


def resolve_pipeline(salt_override: str | None = None) -> PIIShieldPipeline:
    """Return cached pipeline or clone with a per-request salt override."""
    base = get_pipeline()
    if not salt_override:
        return base
    return PIIShieldPipeline(
        detector=base.detector,
        anonymizer=DeterministicAnonymizer(
            salt=salt_override,
            locale=get_settings().locale,
        ),
        default_mode=base.default_mode,
    )


@lru_cache(maxsize=1)
def get_auth_provider() -> AuthProvider:
    """Return active auth provider (defaults to OpenCoreAuthProvider)."""
    return OpenCoreAuthProvider()


@lru_cache(maxsize=1)
def get_audit_sink() -> AuditSink:
    """Return metadata-only audit sink (no-op unless PII_SHIELD_AUDIT_LOG_PATH is set)."""
    raw_path = get_settings().audit_log_path
    return LocalJsonlAuditSink(Path(raw_path) if raw_path else None)
