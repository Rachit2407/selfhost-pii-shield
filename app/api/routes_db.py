"""Relational database schema inspection and FK-preserving anonymization routes."""

from __future__ import annotations

from dataclasses import asdict

from fastapi import APIRouter, Header, HTTPException
from pydantic import BaseModel, Field

from app.api.deps import get_audit_sink, get_auth_provider, resolve_pipeline
from app.connectors.database import anonymize_database, inspect_database
from app.engine.deterministic import AnonymizeMode
from app.enterprise.hooks import AuditEvent

router = APIRouter(prefix="/api/v1/db", tags=["database"])


class DBInspectRequest(BaseModel):
    source_dsn: str = Field(..., description="SQLAlchemy DSN (e.g. sqlite:///samples/sample_prod.sqlite)")
    column_rules: dict[str, str] | None = Field(
        default=None,
        description="Optional overrides formatted as {'table.column': 'EMAIL_ADDRESS'}",
    )


class DBAnonymizeRequest(BaseModel):
    source_dsn: str
    target_dsn: str
    mode: AnonymizeMode = "synthetic"
    column_rules: dict[str, str] | None = None
    truncate_target: bool = True
    salt: str | None = None


@router.post("/inspect")
def inspect_db(req: DBInspectRequest) -> dict:
    """Inspect database schema, topological FK order, and suggested PII rules."""
    try:
        report = inspect_database(req.source_dsn, column_rules=req.column_rules)
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"DB inspection failed: {exc}") from exc
    return asdict(report)


@router.post("/anonymize")
def anonymize_db(
    req: DBAnonymizeRequest,
    authorization: str | None = Header(default=None),
) -> dict:
    """Anonymize source_dsn -> target_dsn preserving PK/FK referential integrity."""
    actor = get_auth_provider().authorize(authorization, required_role="db_admin")
    pipeline = resolve_pipeline(req.salt)
    try:
        report = anonymize_database(
            source_dsn=req.source_dsn,
            target_dsn=req.target_dsn,
            pipeline=pipeline,
            mode=req.mode,
            column_rules=req.column_rules,
            truncate_target=req.truncate_target,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"DB anonymization failed: {exc}") from exc

    get_audit_sink().record(
        AuditEvent(
            action="anonymize_db",
            backend=pipeline.detector.backend_name,
            findings_count=sum(report.fields_anonymized.values()),
            entity_counts=report.fields_anonymized,
            actor=actor,
        )
    )
    return asdict(report)
