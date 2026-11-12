"""Offline-only PII detector powered by Presidio + local spaCy + regex specs."""

from __future__ import annotations

from dataclasses import dataclass
import logging
import re
from typing import Iterable

from app.engine.recognizers import (
    LOCAL_PATTERN_SPECS,
    build_presidio_custom_recognizers,
)

logger = logging.getLogger(__name__)

# Map spaCy entity labels to canonical Presidio entity names.
_SPACY_TO_CANONICAL = {
    "PERSON": "PERSON",
    "ORG": "ORGANIZATION",
    "GPE": "LOCATION",
    "LOC": "LOCATION",
}

# Canonical entity priority for tie-breaking overlapping detections.
_ENTITY_PRIORITY = {
    "SECRET_TOKEN": 100,
    "CREDIT_CARD": 95,
    "IN_AADHAAR": 92,
    "IN_PAN": 90,
    "IN_UPI": 88,
    "EMAIL_ADDRESS": 85,
    "US_SSN": 84,
    "IBAN_CODE": 82,
    "PHONE_NUMBER": 75,
    "IP_ADDRESS": 70,
    "PERSON": 60,
    "ORGANIZATION": 50,
    "LOCATION": 45,
}


@dataclass(frozen=True)
class DetectedSpan:
    """Single detected PII or secret span within input text."""

    entity_type: str
    start: int
    end: int
    score: float
    text: str
    source: str


def resolve_overlaps(spans: Iterable[DetectedSpan]) -> list[DetectedSpan]:
    """Resolve overlapping spans by priority, confidence score, and length."""
    ordered = sorted(
        spans,
        key=lambda s: (
            -_ENTITY_PRIORITY.get(s.entity_type, 40),
            -round(s.score, 4),
            -(s.end - s.start),
            s.start,
        ),
    )
    accepted: list[DetectedSpan] = []
    for candidate in ordered:
        overlaps = any(
            not (candidate.end <= existing.start or candidate.start >= existing.end)
            for existing in accepted
        )
        if not overlaps:
            accepted.append(candidate)
    return sorted(accepted, key=lambda s: s.start)


class LocalPIIDetector:
    """100% offline PII detector using Presidio (when available) and local spaCy/regex."""

    def __init__(
        self,
        spacy_model: str = "en_core_web_sm",
        score_threshold: float = 0.4,
        airgap_strict: bool = True,
    ) -> None:
        self.spacy_model = spacy_model
        self.score_threshold = score_threshold
        self.airgap_strict = airgap_strict
        self.backend_name = "regex+spacy"
        self.spacy_loaded = False
        self.presidio_loaded = False
        self._analyzer = None
        self._nlp = None
        self._compiled_specs = [
            (spec, re.compile(spec.regex)) for spec in LOCAL_PATTERN_SPECS
        ]
        self._init_engines()

    def _init_engines(self) -> None:
        """Initialize local NLP/Presidio engines without network access."""
        import os

        if self.airgap_strict:
            os.environ.setdefault("SPACY_WARNING_IGNORE", "W008")
            # Prevent tldextract (used by Presidio's UrlRecognizer) from making network calls.
            os.environ.setdefault("TLDEXTRACT_CACHE", os.path.join(os.path.expanduser("~"), ".cache", "tldextract_offline"))
            try:
                import tldextract

                tldextract.extract.update(fetch=False)  # type: ignore[attr-defined]
            except Exception:
                pass

        # Verify local spaCy model exists without downloading or double-loading.
        model_available = False
        try:
            import spacy

            model_available = bool(spacy.util.is_package(self.spacy_model))
            if not model_available:
                logger.warning(
                    "Local spaCy model '%s' not found; NER disabled in offline mode.",
                    self.spacy_model,
                )
        except Exception as exc:  # pragma: no cover - defensive fallback
            logger.warning("spaCy check skipped: %s", exc)

        # Prefer Microsoft Presidio Analyzer when installed and spaCy model is local.
        if model_available:
            try:
                from presidio_analyzer import AnalyzerEngine, RecognizerRegistry
                from presidio_analyzer.nlp_engine import NlpEngineProvider

                nlp_config = {
                    "nlp_engine_name": "spacy",
                    "models": [{"lang_code": "en", "model_name": self.spacy_model}],
                }
                nlp_engine = NlpEngineProvider(nlp_configuration=nlp_config).create_engine()
                registry = RecognizerRegistry()
                registry.load_predefined_recognizers(nlp_engine=nlp_engine)
                for recognizer in build_presidio_custom_recognizers():
                    registry.add_recognizer(recognizer)

                self._analyzer = AnalyzerEngine(
                    registry=registry,
                    nlp_engine=nlp_engine,
                    supported_languages=["en"],
                )
                self.spacy_loaded = True
                self.presidio_loaded = True
                self.backend_name = "presidio+spacy"
                return
            except Exception as exc:
                logger.info("Presidio unavailable (%s); using local spaCy+regex engine.", exc)

        if model_available:
            try:
                import spacy

                self._nlp = spacy.load(self.spacy_model)
                self.spacy_loaded = True
            except Exception as exc:  # pragma: no cover
                logger.warning("spaCy load skipped: %s", exc)

    def detect(
        self,
        text: str,
        entities: list[str] | None = None,
        score_threshold: float | None = None,
    ) -> list[DetectedSpan]:
        """Detect PII spans in text completely offline."""
        if not text:
            return []

        threshold = self.score_threshold if score_threshold is None else score_threshold
        allowed = set(entities) if entities else None
        raw_spans: list[DetectedSpan] = []

        if self._analyzer is not None:
            results = self._analyzer.analyze(
                text=text,
                language="en",
                entities=list(allowed) if allowed else None,
                score_threshold=threshold,
            )
            for item in results:
                matched_text = text[item.start : item.end]
                # Enforce custom checksum validators (Aadhaar Verhoeff, Card Luhn) when present.
                if not self._passes_spec_validator(item.entity_type, matched_text):
                    continue
                raw_spans.append(
                    DetectedSpan(
                        entity_type=item.entity_type,
                        start=item.start,
                        end=item.end,
                        score=float(item.score),
                        text=matched_text,
                        source="presidio",
                    )
                )
        else:
            raw_spans.extend(self._detect_regex(text, allowed, threshold))
            raw_spans.extend(self._detect_spacy_ner(text, allowed, threshold))

        # Always run high-precision custom regex patterns (e.g., SECRET_TOKEN, IN_UPI, IN_PAN)
        # to guarantee zero misses even if Presidio scores without context words.
        for span in self._detect_regex(text, allowed, threshold, only_custom=self._analyzer is not None):
            raw_spans.append(span)

        return resolve_overlaps(raw_spans)

    def _detect_regex(
        self,
        text: str,
        allowed: set[str] | None,
        threshold: float,
        only_custom: bool = False,
    ) -> list[DetectedSpan]:
        spans: list[DetectedSpan] = []
        for spec, compiled in self._compiled_specs:
            if only_custom and not spec.presidio_custom:
                continue
            if allowed is not None and spec.entity_type not in allowed:
                continue
            if spec.score < threshold:
                continue
            for match in compiled.finditer(text):
                matched = match.group(0)
                if spec.validator and not spec.validator(matched):
                    continue
                spans.append(
                    DetectedSpan(
                        entity_type=spec.entity_type,
                        start=match.start(),
                        end=match.end(),
                        score=spec.score,
                        text=matched,
                        source="regex",
                    )
                )
        return spans

    def _detect_spacy_ner(
        self,
        text: str,
        allowed: set[str] | None,
        threshold: float,
    ) -> list[DetectedSpan]:
        if self._nlp is None or 0.65 < threshold:
            return []
        doc = self._nlp(text)
        spans: list[DetectedSpan] = []
        for ent in doc.ents:
            canonical = _SPACY_TO_CANONICAL.get(ent.label_)
            if not canonical:
                continue
            if allowed is not None and canonical not in allowed:
                continue
            spans.append(
                DetectedSpan(
                    entity_type=canonical,
                    start=ent.start_char,
                    end=ent.end_char,
                    score=0.7,
                    text=ent.text,
                    source="spacy",
                )
            )
        return spans

    @staticmethod
    def _passes_spec_validator(entity_type: str, matched_text: str) -> bool:
        for spec in LOCAL_PATTERN_SPECS:
            if spec.entity_type == entity_type and spec.validator is not None:
                return spec.validator(matched_text)
        return True
