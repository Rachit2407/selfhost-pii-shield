"""Deterministic HMAC-SHA256 keyed replacement and format-preserving generators."""

from __future__ import annotations

import hashlib
import hmac
import random
import re
import threading
import uuid
from typing import Literal

from faker import Faker

from app.engine.recognizers import compute_verhoeff_check_digit


AnonymizeMode = Literal["synthetic", "redact"]


def _luhn_check_digit(partial_digits: str) -> str:
    """Calculate the Luhn check digit for a partial card number."""
    digits = [int(ch) for ch in partial_digits]
    checksum = 0
    # Including the upcoming check digit at the end means parity flips.
    for idx, digit in enumerate(reversed(digits)):
        val = digit * 2 if idx % 2 == 0 else digit
        if val > 9:
            val -= 9
        checksum += val
    return str((10 - (checksum % 10)) % 10)


class DeterministicAnonymizer:
    """Maps sensitive values deterministically using HMAC-SHA256 + seeded Faker."""

    def __init__(self, salt: str, locale: str = "en_IN") -> None:
        self._salt_bytes = salt.encode("utf-8")
        self._locale = locale
        self._faker = Faker(locale)
        self._lock = threading.Lock()

    @staticmethod
    def normalize_value(entity_type: str, raw_value: str) -> str:
        """Canonicalize values so minor formatting differences hash identically."""
        stripped = raw_value.strip()
        if entity_type in ("EMAIL_ADDRESS", "IN_UPI"):
            return stripped.lower()
        if entity_type in ("IN_PAN",):
            return stripped.upper()
        if entity_type in ("IN_AADHAAR", "CREDIT_CARD", "PHONE_NUMBER"):
            return re.sub(r"[\s()-]", "", stripped)
        if entity_type == "PERSON":
            return re.sub(r"\s+", " ", stripped).lower()
        return stripped

    def derive_digest(
        self,
        entity_type: str,
        raw_value: str,
        collision_index: int = 0,
    ) -> bytes:
        """Compute keyed HMAC-SHA256 digest for (entity_type, normalized_value)."""
        normalized = self.normalize_value(entity_type, raw_value)
        msg = f"{entity_type}:{normalized}"
        if collision_index > 0:
            msg = f"{msg}#{collision_index}"
        return hmac.new(self._salt_bytes, msg.encode("utf-8"), hashlib.sha256).digest()

    def anonymize(
        self,
        entity_type: str,
        raw_value: str,
        mode: AnonymizeMode = "synthetic",
        collision_index: int = 0,
    ) -> str:
        """Return a deterministic synthetic or redacted replacement."""
        digest = self.derive_digest(entity_type, raw_value, collision_index=collision_index)
        short_tag = digest[:3].hex().upper()

        if mode == "redact":
            if entity_type == "SECRET_TOKEN":
                return f"[REDACTED_SECRET_{short_tag}]"
            return f"[{entity_type}_{short_tag}]"

        seed_int = int.from_bytes(digest[:8], "big")
        rng = random.Random(seed_int)

        if entity_type == "PERSON":
            return self._seeded_faker(seed_int, lambda f: f.name())

        if entity_type == "ORGANIZATION":
            return self._seeded_faker(seed_int, lambda f: f.company())

        if entity_type in ("LOCATION", "GPE", "LOC"):
            return self._seeded_faker(seed_int, lambda f: f.city())

        if entity_type == "EMAIL_ADDRESS":
            first = self._seeded_faker(seed_int, lambda f: f.first_name())
            last = self._seeded_faker(seed_int ^ 0x9E3779B9, lambda f: f.last_name())
            slug = re.sub(r"[^a-z0-9]", "", f"{first}.{last}".lower())
            first_clean = re.sub(r"[^a-z0-9]", "", first.lower()) or "user"
            last_clean = re.sub(r"[^a-z0-9]", "", last.lower()) or "synth"
            _ = slug
            return f"{first_clean}.{last_clean}.{digest[:2].hex()}@synthetic.local"

        if entity_type == "IN_UPI":
            handle = self._seeded_faker(seed_int, lambda f: f.first_name()).lower()
            handle_clean = re.sub(r"[^a-z0-9]", "", handle) or "payer"
            return f"{handle_clean}.{digest[:2].hex()}@upi.synthetic"

        if entity_type == "PHONE_NUMBER":
            return self._synthetic_phone(raw_value, rng)

        if entity_type == "IN_PAN":
            letters1 = "".join(rng.choices("ABCDEFGHJKLMNPQRSTUVWXYZ", k=3))
            fourth = "P"
            fifth = rng.choice("ABCDEFGHJKLMNPQRSTUVWXYZ")
            digits = "".join(rng.choices("0123456789", k=4))
            last = rng.choice("ABCDEFGHJKLMNPQRSTUVWXYZ")
            return f"{letters1}{fourth}{fifth}{digits}{last}"

        if entity_type == "IN_AADHAAR":
            first_digit = rng.choice("23456789")
            body = first_digit + "".join(rng.choices("0123456789", k=10))
            full = body + compute_verhoeff_check_digit(body)
            if " " in raw_value:
                return f"{full[:4]} {full[4:8]} {full[8:]}"
            if "-" in raw_value:
                return f"{full[:4]}-{full[4:8]}-{full[8:]}"
            return full

        if entity_type == "CREDIT_CARD":
            body = "400000" + "".join(rng.choices("0123456789", k=9))
            full = body + _luhn_check_digit(body)
            if "-" in raw_value:
                return f"{full[:4]}-{full[4:8]}-{full[8:12]}-{full[12:]}"
            if " " in raw_value:
                return f"{full[:4]} {full[4:8]} {full[8:12]} {full[12:]}"
            return full

        if entity_type == "US_SSN":
            # 900-series numbers are never issued by the SSA.
            p1 = rng.randint(900, 999)
            p2 = rng.randint(10, 99)
            p3 = rng.randint(1000, 9999)
            return f"{p1}-{p2}-{p3}"

        if entity_type == "IP_ADDRESS":
            return f"10.{digest[0]}.{digest[1]}.{max(1, min(254, digest[2]))}"

        if entity_type == "IBAN_CODE":
            digits = "".join(rng.choices("0123456789", k=16))
            return f"XX00SYNTH{digits}"

        if entity_type == "SECRET_TOKEN":
            return f"sk_redacted_{digest[:6].hex()}"

        if entity_type == "SURROGATE_UUID":
            return str(uuid.UUID(bytes=digest[:16], version=4))

        if entity_type == "SURROGATE_ID":
            return str(int.from_bytes(digest[:6], "big") % 900_000_000 + 100_000_000)

        return f"[{entity_type}_{short_tag}]"

    def _seeded_faker(self, seed_int: int, fn) -> str:
        with self._lock:
            self._faker.seed_instance(seed_int)
            return fn(self._faker)

    @staticmethod
    def _synthetic_phone(raw_value: str, rng: random.Random) -> str:
        # Use reserved synthetic/non-routable style blocks when possible.
        if raw_value.strip().startswith("+91"):
            tail = "".join(rng.choices("0123456789", k=7))
            sep = "-" if "-" in raw_value else " "
            return f"+91{sep}900{tail}"
        if raw_value.strip().startswith("+1"):
            tail = "".join(rng.choices("0123456789", k=4))
            return f"+1-555-010-{tail}"
        tail = "".join(rng.choices("0123456789", k=7))
        return f"900{tail}"
