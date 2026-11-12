"""Tests for HMAC-SHA256 deterministic replacement and format preservation."""

from app.engine.deterministic import DeterministicAnonymizer
from app.engine.recognizers import is_valid_luhn, is_valid_verhoeff


def test_same_salt_produces_identical_output():
    a1 = DeterministicAnonymizer(salt="secret-salt-1", locale="en_IN")
    a2 = DeterministicAnonymizer(salt="secret-salt-1", locale="en_IN")

    val = "Aarav.Sharma@Example.com"
    assert a1.anonymize("EMAIL_ADDRESS", val) == a2.anonymize("EMAIL_ADDRESS", val)
    # Canonical normalization should match lowercase too.
    assert a1.anonymize("EMAIL_ADDRESS", val) == a2.anonymize("EMAIL_ADDRESS", val.lower())


def test_different_salt_produces_distinct_output():
    a1 = DeterministicAnonymizer(salt="salt-alpha", locale="en_IN")
    a2 = DeterministicAnonymizer(salt="salt-beta", locale="en_IN")

    out1 = a1.anonymize("EMAIL_ADDRESS", "rachit@example.com")
    out2 = a2.anonymize("EMAIL_ADDRESS", "rachit@example.com")
    assert out1 != out2
    assert out1.endswith("@synthetic.local")


def test_format_preserving_synthetic_tokens_pass_validators():
    anon = DeterministicAnonymizer(salt="format-salt", locale="en_IN")

    aadhaar = anon.anonymize("IN_AADHAAR", "4991 1866 5246")
    assert " " in aadhaar
    assert is_valid_verhoeff(aadhaar)

    card = anon.anonymize("CREDIT_CARD", "4111-1111-1111-1111")
    assert "-" in card
    assert is_valid_luhn(card)

    ip = anon.anonymize("IP_ADDRESS", "203.0.113.42")
    assert ip.startswith("10.")

    secret = anon.anonymize("SECRET_TOKEN", "sk-proj-secret123456789012345678")
    assert secret.startswith("sk_redacted_")


def test_collision_index_generates_distinct_values():
    anon = DeterministicAnonymizer(salt="collision-salt", locale="en_IN")
    v0 = anon.anonymize("EMAIL_ADDRESS", "user@example.com", collision_index=0)
    v1 = anon.anonymize("EMAIL_ADDRESS", "user@example.com", collision_index=1)
    assert v0 != v1
