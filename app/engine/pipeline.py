"""End-to-end PII scrubbing pipeline orchestrating detection and replacement."""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from typing import Any

from app.engine.deterministic import AnonymizeMode, DeterministicAnonymizer
from app.engine.detector import DetectedSpan, LocalPIIDetector


@dataclass
class ScrubFinding:
    """Audit-safe summary of a scrubbed entity (never logs raw plaintext in reports)."""

    entity_type: str
    start: int
    end: int
    score: float
    replacement: str
    source: str


@dataclass
class ScrubResult:
    """Result returned by text/JSON scrubbing operations."""

    scrubbed_text: str
    findings_count: int
    entity_counts: dict[str, int] = field(default_factory=dict)
    findings: list[ScrubFinding] = field(default_factory=list)
    backend: str = ""


class PIIShieldPipeline:
    """Coordinates offline detection + deterministic replacement across text and JSON."""

    def __init__(
        self,
        detector: LocalPIIDetector,
        anonymizer: DeterministicAnonymizer,
        default_mode: AnonymizeMode = "synthetic",
    ) -> None:
        self.detector = detector
        self.anonymizer = anonymizer
        self.default_mode = default_mode

    def scrub_text(
        self,
        text: str,
        mode: AnonymizeMode | None = None,
        entities: list[str] | None = None,
        score_threshold: float | None = None,
    ) -> ScrubResult:
        """Detect PII in text and replace spans deterministically."""
        active_mode = mode or self.default_mode
        spans: list[DetectedSpan] = self.detector.detect(
            text=text,
            entities=entities,
            score_threshold=score_threshold,
        )
        if not spans:
            return ScrubResult(
                scrubbed_text=text,
                findings_count=0,
                entity_counts={},
                findings=[],
                backend=self.detector.backend_name,
            )

        out_parts: list[str] = []
        cursor = 0
        counts: Counter[str] = Counter()
        findings: list[ScrubFinding] = []

        for span in spans:
            out_parts.append(text[cursor : span.start])
            replacement = self.anonymizer.anonymize(
                entity_type=span.entity_type,
                raw_value=span.text,
                mode=active_mode,
            )
            out_parts.append(replacement)
            cursor = span.end
            counts[span.entity_type] += 1
            findings.append(
                ScrubFinding(
                    entity_type=span.entity_type,
                    start=span.start,
                    end=span.end,
                    score=span.score,
                    replacement=replacement,
                    source=span.source,
                )
            )

        out_parts.append(text[cursor:])
        return ScrubResult(
            scrubbed_text="".join(out_parts),
            findings_count=len(findings),
            entity_counts=dict(counts),
            findings=findings,
            backend=self.detector.backend_name,
        )

    def scrub_json_value(
        self,
        payload: Any,
        mode: AnonymizeMode | None = None,
        entities: list[str] | None = None,
        score_threshold: float | None = None,
        _counts: Counter[str] | None = None,
    ) -> tuple[Any, dict[str, int]]:
        """Recursively scrub string values inside nested JSON dicts/lists."""
        counts = _counts if _counts is not None else Counter()

        if isinstance(payload, str):
            res = self.scrub_text(
                payload,
                mode=mode,
                entities=entities,
                score_threshold=score_threshold,
            )
            counts.update(res.entity_counts)
            return res.scrubbed_text, dict(counts)

        if isinstance(payload, list):
            cleaned_list = [
                self.scrub_json_value(
                    item,
                    mode=mode,
                    entities=entities,
                    score_threshold=score_threshold,
                    _counts=counts,
                )[0]
                for item in payload
            ]
            return cleaned_list, dict(counts)

        if isinstance(payload, dict):
            cleaned_dict = {
                key: self.scrub_json_value(
                    val,
                    mode=mode,
                    entities=entities,
                    score_threshold=score_threshold,
                    _counts=counts,
                )[0]
                for key, val in payload.items()
            }
            return cleaned_dict, dict(counts)

        return payload, dict(counts)
