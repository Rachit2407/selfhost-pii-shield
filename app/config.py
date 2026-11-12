"""Application configuration with strict air-gap defaults."""

from functools import lru_cache
from typing import Literal

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Runtime settings loaded from environment variables or local .env file."""

    model_config = SettingsConfigDict(
        env_prefix="PII_SHIELD_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    salt: str = "dev-local-salt-change-in-production"
    mode: Literal["synthetic", "redact"] = "synthetic"
    airgap_strict: bool = True
    score_threshold: float = 0.4
    locale: str = "en_IN"
    spacy_model: str = "en_core_web_sm"
    host: str = "0.0.0.0"
    port: int = 8080
    audit_log_path: str | None = None


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Return cached application settings."""
    return Settings()
