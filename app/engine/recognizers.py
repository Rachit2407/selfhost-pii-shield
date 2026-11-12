"""Canonical local PII pattern definitions for Presidio and offline fallback."""

from __future__ import annotations

from dataclasses import dataclass
import re
from typing import Callable


# Verhoeff tables for Indian Aadhaar 12-digit checksum validation.
_VERHOEFF_D = (
    (0, 1, 2, 3, 4, 5, 6, 7, 8, 9),
    (1, 2, 3, 4, 0, 6, 7, 8, 9, 5),
    (2, 3, 4, 0, 1, 7, 8, 9, 5, 6),
    (3, 4, 0, 1, 2, 8, 9, 5, 6, 7),
    (4, 0, 1, 2, 3, 9, 5, 6, 7, 8),
    (5, 9, 8, 7, 6, 0, 4, 3, 2, 1),
    (6, 5, 9, 8, 7, 1, 0, 4, 3, 2),
    (7, 6, 5, 9, 8, 2, 1, 0, 4, 3),
    (8, 7, 6, 5, 9, 3, 2, 1, 0, 4),
    (9, 8, 7, 6, 5, 4, 3, 2, 1, 0),
)
_VERHOEFF_P = (
    (0, 1, 2, 3, 4, 5, 6, 7, 8, 9),
    (1, 5, 7, 6, 2, 8, 3, 0, 9, 4),
    (5, 8, 0, 3, 7, 9, 6, 1, 4, 2),
    (8, 9, 1, 6, 0, 4, 3, 5, 2, 7),
    (9, 4, 5, 3, 1, 2, 6, 8, 7, 0),
    (4, 2, 8, 6, 5, 7, 3, 9, 0, 1),
    (2, 7, 9, 3, 8, 0, 6, 4, 1, 5),
    (7, 0, 4, 6, 9, 1, 3, 2, 5, 8),
)


def is_valid_verhoeff(digits_str: str) -> bool:
    """Validate a numeric string against the Verhoeff check digit algorithm."""
    cleaned = re.sub(r"\D", "", digits_str)
    if len(cleaned) != 12 or cleaned[0] in ("0", "1"):
        return False
    c = 0
    for idx, ch in enumerate(reversed(cleaned)):
        c = _VERHOEFF_D[c][_VERHOEFF_P[idx % 8][int(ch)]]
    return c == 0


def compute_verhoeff_check_digit(eleven_digits: str) -> str:
    """Compute the Verhoeff check digit for an 11-digit Aadhaar body."""
    inv = (0, 4, 3, 2, 1, 5, 6, 7, 8, 9)
    c = 0
    for idx, ch in enumerate(reversed(eleven_digits)):
        c = _VERHOEFF_D[c][_VERHOEFF_P[(idx + 1) % 8][int(ch)]]
    return str(inv[c])


def is_valid_luhn(number_str: str) -> bool:
    """Validate payment card numbers with the Luhn checksum."""
    digits = [int(ch) for ch in re.sub(r"\D", "", number_str)]
    if not 13 <= len(digits) <= 19:
        return False
    checksum = 0
    parity = len(digits) % 2
    for idx, digit in enumerate(digits):
        if idx % 2 == parity:
            digit *= 2
            if digit > 9:
                digit -= 9
        checksum += digit
    return checksum % 10 == 0


@dataclass(frozen=True)
class LocalPatternSpec:
    """Single source of truth for regex-based PII and secret recognizers."""

    entity_type: str
    pattern_name: str
    regex: str
    score: float
    context: tuple[str, ...] = ()
    validator: Callable[[str], bool] | None = None
    presidio_custom: bool = True


# Canonical pattern table shared between Presidio custom recognizers and fallback regex engine.
LOCAL_PATTERN_SPECS: tuple[LocalPatternSpec, ...] = (
    LocalPatternSpec(
        entity_type="SECRET_TOKEN",
        pattern_name="api_key_jwt_pat",
        regex=(
            r"\b(?:"
            r"AKIA[0-9A-Z]{16}|"
            r"eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}|"
            r"(?:sk|pk)_(?:live|test)_[0-9A-Za-z]{16,}|"
            r"sk-[A-Za-z0-9_-]{20,}|"
            r"(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{20,}"
            r")\b"
        ),
        score=0.95,
        context=("token", "secret", "api_key", "bearer", "authorization"),
        presidio_custom=True,
    ),
    LocalPatternSpec(
        entity_type="IN_PAN",
        pattern_name="indian_pan_card",
        regex=r"\b[A-Z]{5}[0-9]{4}[A-Z]\b",
        score=0.85,
        context=("pan", "permanent account", "tax", "kyc"),
        presidio_custom=True,
    ),
    LocalPatternSpec(
        entity_type="IN_AADHAAR",
        pattern_name="indian_aadhaar_number",
        regex=r"\b[2-9][0-9]{3}[\s-]?[0-9]{4}[\s-]?[0-9]{4}\b",
        score=0.88,
        context=("aadhaar", "aadhar", "uidai", "kyc"),
        validator=is_valid_verhoeff,
        presidio_custom=True,
    ),
    LocalPatternSpec(
        entity_type="IN_UPI",
        pattern_name="indian_upi_vpa",
        regex=(
            r"\b[a-zA-Z0-9._-]{2,}@"
            r"(?:okaxis|oksbi|okicici|okhdfcbank|ybl|ibl|axl|paytm|upi|apl|pingpay|sbi|icici|hdfc)\b"
        ),
        score=0.88,
        context=("upi", "vpa", "payment", "gpay", "phonepe"),
        presidio_custom=True,
    ),
    LocalPatternSpec(
        entity_type="EMAIL_ADDRESS",
        pattern_name="email_rfc_basic",
        regex=r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b",
        score=0.90,
        presidio_custom=False,
    ),
    LocalPatternSpec(
        entity_type="CREDIT_CARD",
        pattern_name="payment_card_luhn",
        regex=r"\b(?:4[0-9]{3}|5[1-5][0-9]{2}|3[47][0-9]{2}|6(?:011|5[0-9]{2}))(?:[\s-]?[0-9]{4}){2,3}\b",
        score=0.90,
        validator=is_valid_luhn,
        presidio_custom=False,
    ),
    LocalPatternSpec(
        entity_type="US_SSN",
        pattern_name="us_ssn_dashed",
        regex=r"\b(?!000|666|9\d\d)[0-9]{3}-(?!00)[0-9]{2}-(?!0000)[0-9]{4}\b",
        score=0.85,
        presidio_custom=False,
    ),
    LocalPatternSpec(
        entity_type="PHONE_NUMBER",
        pattern_name="intl_and_indian_phone",
        regex=r"(?:\+91[\s-]?[6-9][0-9]{9}|\+1[\s-]?(?:\([2-9][0-9]{2}\)|[2-9][0-9]{2})[\s-]?[0-9]{3}[\s-]?[0-9]{4}|\b[6-9][0-9]{9}\b)",
        score=0.72,
        presidio_custom=False,
    ),
    LocalPatternSpec(
        entity_type="IP_ADDRESS",
        pattern_name="ipv4_address",
        regex=r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b",
        score=0.75,
        presidio_custom=False,
    ),
)


def build_presidio_custom_recognizers():
    """Instantiate Presidio PatternRecognizer objects from LOCAL_PATTERN_SPECS."""
    from presidio_analyzer import Pattern, PatternRecognizer

    recognizers = []
    for spec in LOCAL_PATTERN_SPECS:
        if not spec.presidio_custom:
            continue
        pattern = Pattern(
            name=spec.pattern_name,
            regex=spec.regex,
            score=spec.score,
        )
        recognizers.append(
            PatternRecognizer(
                supported_entity=spec.entity_type,
                patterns=[pattern],
                context=list(spec.context) if spec.context else None,
            )
        )
    return recognizers
