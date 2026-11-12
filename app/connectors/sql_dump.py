"""Streaming scrubber for .sql dump exports and .jsonl streams."""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
import json
import re
from typing import Iterable

from app.engine.deterministic import AnonymizeMode
from app.engine.pipeline import PIIShieldPipeline

# Matches single-quoted SQL string literals while preserving escaped quotes ('').
_SQL_STRING_LITERAL_RE = re.compile(r"'((?:[^']|'')*)'")


@dataclass
class DumpScrubSummary:
    """Summary metrics from scrubbing a SQL or JSONL stream."""

    lines_processed: int
    findings_count: int
    entity_counts: dict[str, int]


def scrub_sql_lines(
    lines: Iterable[str],
    pipeline: PIIShieldPipeline,
    mode: AnonymizeMode | None = None,
) -> tuple[list[str], DumpScrubSummary]:
    """Scrub PII inside SQL INSERT/VALUES string literals while leaving DDL intact."""
    out_lines: list[str] = []
    counts: Counter[str] = Counter()
    line_count = 0

    for line in lines:
        line_count += 1
        stripped = line.lstrip().upper()
        # Only scrub data-bearing statements (INSERT / COPY / VALUES), not CREATE/ALTER DDL.
        if not (
            stripped.startswith("INSERT ")
            or stripped.startswith("VALUES")
            or "'" in line and (stripped.startswith("(") or "VALUES" in stripped)
        ):
            out_lines.append(line)
            continue

        def _replace_literal(match: re.Match[str]) -> str:
            raw_inner = match.group(1).replace("''", "'")
            if not raw_inner.strip():
                return match.group(0)
            res = pipeline.scrub_text(raw_inner, mode=mode)
            if res.findings_count == 0:
                return match.group(0)
            counts.update(res.entity_counts)
            escaped = res.scrubbed_text.replace("'", "''")
            return f"'{escaped}'"

        out_lines.append(_SQL_STRING_LITERAL_RE.sub(_replace_literal, line))

    return out_lines, DumpScrubSummary(
        lines_processed=line_count,
        findings_count=sum(counts.values()),
        entity_counts=dict(counts),
    )


def scrub_jsonl_lines(
    lines: Iterable[str],
    pipeline: PIIShieldPipeline,
    mode: AnonymizeMode | None = None,
) -> tuple[list[str], DumpScrubSummary]:
    """Stream-scrub newline-delimited JSON records."""
    out_lines: list[str] = []
    counts: Counter[str] = Counter()
    line_count = 0

    for line in lines:
        if not line.strip():
            continue
        line_count += 1
        obj = json.loads(line)
        cleaned, line_counts = pipeline.scrub_json_value(obj, mode=mode)
        counts.update(line_counts)
        out_lines.append(json.dumps(cleaned, ensure_ascii=False))

    return out_lines, DumpScrubSummary(
        lines_processed=line_count,
        findings_count=sum(counts.values()),
        entity_counts=dict(counts),
    )
