"""Text, JSON, and document scrubbing endpoints."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, File, Form, Header, HTTPException, UploadFile
from pydantic import BaseModel, Field

from app.api.deps import get_audit_sink, get_auth_provider, resolve_pipeline
from app.connectors.documents import scrub_document_bytes
from app.engine.deterministic import AnonymizeMode
from app.enterprise.hooks import AuditEvent

router = APIRouter(prefix="/api/v1/scrub", tags=["scrub"])


class ScrubTextRequest(BaseModel):
    text: str = Field(..., description="Raw text or LLM prompt to sanitize locally.")
    mode: AnonymizeMode | None = Field(default=None, description="'synthetic' or 'redact'")
    entities: list[str] | None = Field(default=None, description="Optional entity whitelist")
    score_threshold: float | None = Field(default=None, ge=0.0, le=1.0)
    salt: str | None = Field(default=None, description="Optional per-request salt override")


class ScrubFindingOut(BaseModel):
    entity_type: str
    start: int
    end: int
    score: float
    replacement: str
    source: str


class ScrubTextResponse(BaseModel):
    scrubbed_text: str
    findings_count: int
    entity_counts: dict[str, int]
    findings: list[ScrubFindingOut]
    backend: str


class ScrubJsonRequest(BaseModel):
    payload: Any
    mode: AnonymizeMode | None = None
    entities: list[str] | None = None
    score_threshold: float | None = Field(default=None, ge=0.0, le=1.0)
    salt: str | None = None


@router.post("/text", response_model=ScrubTextResponse)
def scrub_text(
    req: ScrubTextRequest,
    authorization: str | None = Header(default=None),
) -> ScrubTextResponse:
    """Scrub raw text or LLM prompts deterministically in-memory."""
    actor = get_auth_provider().authorize(authorization, required_role="operator")
    pipeline = resolve_pipeline(req.salt)
    res = pipeline.scrub_text(
        text=req.text,
        mode=req.mode,
        entities=req.entities,
        score_threshold=req.score_threshold,
    )
    get_audit_sink().record(
        AuditEvent(
            action="scrub_text",
            backend=res.backend,
            findings_count=res.findings_count,
            entity_counts=res.entity_counts,
            actor=actor,
        )
    )
    return ScrubTextResponse(
        scrubbed_text=res.scrubbed_text,
        findings_count=res.findings_count,
        entity_counts=res.entity_counts,
        findings=[
            ScrubFindingOut(
                entity_type=f.entity_type,
                start=f.start,
                end=f.end,
                score=f.score,
                replacement=f.replacement,
                source=f.source,
            )
            for f in res.findings
        ],
        backend=res.backend,
    )


@router.post("/json")
def scrub_json(
    req: ScrubJsonRequest,
    authorization: str | None = Header(default=None),
) -> dict:
    """Recursively scrub strings inside arbitrary JSON payloads."""
    actor = get_auth_provider().authorize(authorization, required_role="operator")
    pipeline = resolve_pipeline(req.salt)
    cleaned, counts = pipeline.scrub_json_value(
        req.payload,
        mode=req.mode,
        entities=req.entities,
        score_threshold=req.score_threshold,
    )
    total = sum(counts.values())
    get_audit_sink().record(
        AuditEvent(
            action="scrub_json",
            backend=pipeline.detector.backend_name,
            findings_count=total,
            entity_counts=counts,
            actor=actor,
        )
    )
    return {
        "scrubbed_payload": cleaned,
        "findings_count": total,
        "entity_counts": counts,
        "backend": pipeline.detector.backend_name,
    }


@router.post("/file")
async def scrub_file(
    file: UploadFile = File(...),
    mode: AnonymizeMode | None = Form(default=None),
    salt: str | None = Form(default=None),
    authorization: str | None = Header(default=None),
) -> dict:
    """Scrub an uploaded TXT, MD, CSV, JSON, JSONL, SQL, or PDF file locally."""
    actor = get_auth_provider().authorize(authorization, required_role="operator")
    raw_bytes = await file.read()
    if not raw_bytes:
        raise HTTPException(status_code=400, detail="Uploaded file is empty.")
    pipeline = resolve_pipeline(salt)
    try:
        res = scrub_document_bytes(
            filename=file.filename or "document.txt",
            raw_bytes=raw_bytes,
            pipeline=pipeline,
            mode=mode,
        )
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"Failed to parse document: {exc}") from exc

    get_audit_sink().record(
        AuditEvent(
            action="scrub_file",
            backend=res.backend,
            findings_count=res.findings_count,
            entity_counts=res.entity_counts,
            actor=actor,
        )
    )

    return {
        "filename": res.filename,
        "content_type": res.content_type,
        "scrubbed_content": res.scrubbed_content,
        "findings_count": res.findings_count,
        "entity_counts": res.entity_counts,
        "backend": res.backend,
    }
