"""Tests for local PII & secret recognizers and overlap resolution."""

from app.api.deps import get_pipeline
from app.engine.recognizers import compute_verhoeff_check_digit, is_valid_verhoeff


def _valid_sample_aadhaar() -> str:
    body = "49911866524"
    full = body + compute_verhoeff_check_digit(body)
    assert is_valid_verhoeff(full)
    return f"{full[:4]} {full[4:8]} {full[8:]}"


def test_detects_indian_and_global_pii_and_secrets():
    detector = get_pipeline().detector
    aadhaar = _valid_sample_aadhaar()
    sample = (
        f"Contact Aarav Sharma at aarav@acme.in or +91-9876543210. "
        f"PAN: ABCDE1234F, Aadhaar: {aadhaar}, UPI: aarav@okicici, "
        f"IP: 203.0.113.10, Token: AKIAIOSFODNN7EXAMPLE"
    )
    spans = detector.detect(sample)
    found_types = {s.entity_type for s in spans}

    assert "EMAIL_ADDRESS" in found_types
    assert "PHONE_NUMBER" in found_types
    assert "IN_PAN" in found_types
    assert "IN_AADHAAR" in found_types
    assert "IN_UPI" in found_types
    assert "IP_ADDRESS" in found_types
    assert "SECRET_TOKEN" in found_types


def test_invalid_aadhaar_checksum_is_rejected():
    detector = get_pipeline().detector
    bad_body = "49911866524"
    good_check = int(compute_verhoeff_check_digit(bad_body))
    bad_check = (good_check + 1) % 10
    invalid_aadhaar = f"{bad_body[:4]} {bad_body[4:8]} {bad_body[8:]}{bad_check}"

    spans = detector.detect(f"Reference ID: {invalid_aadhaar}")
    assert all(s.entity_type != "IN_AADHAAR" for s in spans)
