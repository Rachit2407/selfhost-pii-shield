"""Document and structured-file PII scrubbing connector (TXT, MD, JSON, CSV, PDF)."""

from __future__ import annotations

import csv
import io
import json
from dataclasses import dataclass
from typing import Any

from pypdf import PdfReader

from app.connectors.sql_dump import scrub_jsonl_lines, scrub_sql_lines
from app.engine.deterministic import AnonymizeMode
from app.engine.pipeline import PIIShieldPipeline


@dataclass
class DocumentScrubResponse:
    """Result of scrubbing an uploaded or local document."""

    filename: str
    content_type: str
    scrubbed_content: str
    findings_count: int
    entity_counts: dict[str, int]
    backend: str


def scrub_document_bytes(
    filename: str,
    raw_bytes: bytes,
    pipeline: PIIShieldPipeline,
    mode: AnonymizeMode | None = None,
    entities: list[str] | None = None,
    score_threshold: float | None = None,
) -> DocumentScrubResponse:
    """Scrub plaintext, markdown, CSV, JSON, JSONL, or PDF bytes completely offline."""
    lower = filename.lower()

    if lower.endswith(".pdf"):
        reader = PdfReader(io.BytesIO(raw_bytes))
        pages_text = [page.extract_text() or "" for page in reader.pages]
        joined = "\n\n--- PAGE BREAK ---\n\n".join(pages_text)
        res = pipeline.scrub_text(
            joined, mode=mode, entities=entities, score_threshold=score_threshold
        )
        return DocumentScrubResponse(
            filename=filename,
            content_type="text/plain",
            scrubbed_content=res.scrubbed_text,
            findings_count=res.findings_count,
            entity_counts=res.entity_counts,
            backend=res.backend,
        )

    decoded = raw_bytes.decode("utf-8", errors="replace")

    if lower.endswith(".json"):
        data: Any = json.loads(decoded)
        cleaned, counts = pipeline.scrub_json_value(
            data, mode=mode, entities=entities, score_threshold=score_threshold
        )
        return DocumentScrubResponse(
            filename=filename,
            content_type="application/json",
            scrubbed_content=json.dumps(cleaned, indent=2, ensure_ascii=False),
            findings_count=sum(counts.values()),
            entity_counts=counts,
            backend=pipeline.detector.backend_name,
        )

    if lower.endswith(".jsonl") or lower.endswith(".ndjson"):
        lines_out, summary = scrub_jsonl_lines(
            decoded.splitlines(), pipeline=pipeline, mode=mode
        )
        return DocumentScrubResponse(
            filename=filename,
            content_type="application/x-ndjson",
            scrubbed_content="\n".join(lines_out),
            findings_count=summary.findings_count,
            entity_counts=summary.entity_counts,
            backend=pipeline.detector.backend_name,
        )

    if lower.endswith(".sql"):
        lines_out, summary = scrub_sql_lines(
            decoded.splitlines(), pipeline=pipeline, mode=mode
        )
        return DocumentScrubResponse(
            filename=filename,
            content_type="application/sql",
            scrubbed_content="\n".join(lines_out),
            findings_count=summary.findings_count,
            entity_counts=summary.entity_counts,
            backend=pipeline.detector.backend_name,
        )

    if lower.endswith(".csv"):
        reader = csv.reader(io.StringIO(decoded))
        output = io.StringIO()
        writer = csv.writer(output, lineterminator="\n")
        total_counts = {}
        for row_idx, row in enumerate(reader):
            if row_idx == 0:
                writer.writerow(row)
                continue
            cleaned_row: list[str] = []
            for cell in row:
                res = pipeline.scrub_text(
                    cell, mode=mode, entities=entities, score_threshold=score_threshold
                )
                for k, v in res.entity_counts.items():
                    total_counts[k] = total_counts.get(k, 0) + v
                cleaned_row.append(res.scrubbed_text)
            writer.writerow(cleaned_row)
        return DocumentScrubResponse(
            filename=filename,
            content_type="text/csv",
            scrubbed_content=output.getvalue(),
            findings_count=sum(total_counts.values()),
            entity_counts=total_counts,
            backend=pipeline.detector.backend_name,
        )

    res = pipeline.scrub_text(
        decoded, mode=mode, entities=entities, score_threshold=score_threshold
    )
    return DocumentScrubResponse(
        filename=filename,
        content_type="text/plain",
        scrubbed_content=res.scrubbed_text,
        findings_count=res.findings_count,
        entity_counts=res.entity_counts,
        backend=res.backend,
    )
