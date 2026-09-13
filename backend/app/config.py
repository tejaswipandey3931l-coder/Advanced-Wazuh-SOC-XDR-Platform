"""
Application configuration.

All settings are loaded from environment variables / .env file.
No secrets should ever appear in source code.
"""

from __future__ import annotations

from functools import lru_cache
from typing import Literal

from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Centralised application settings.

    Values are resolved from (highest to lowest priority):
      1. Environment variables
      2. .env file at the project root
      3. Field defaults below
    """

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # ── Application ──────────────────────────────────────────────────────────
    app_name: str = "Advanced Wazuh SOC"
    app_version: str = "0.1.0"
    app_debug: bool = False
    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"] = "INFO"

    # ── Wazuh API ────────────────────────────────────────────────────────────
    wazuh_api_url: str = "https://127.0.0.1:55000"
    wazuh_api_user: str
    wazuh_api_password: str
    wazuh_verify_ssl: bool = True
    wazuh_ca_cert: str | None = None
    wazuh_api_timeout: float = 10.0
    wazuh_api_max_retries: int = 3

    # ── Database (PostgreSQL via asyncpg) ────────────────────────────────────
    soc_db_url: str  # e.g. postgresql+asyncpg://user:pass@host:5432/dbname
    soc_db_pool_size: int = 5
    soc_db_max_overflow: int = 10
    soc_db_echo: bool = False  # set True only for deep SQL debugging

    # ── Redis ─────────────────────────────────────────────────────────────────
    soc_redis_url: str = "redis://127.0.0.1:6379/0"

    # ── OpenSearch / Wazuh Indexer (Phase 1+) ────────────────────────────────
    opensearch_url: str = "https://127.0.0.1:9200"
    opensearch_user: str = ""
    opensearch_password: str = ""
    opensearch_verify_ssl: bool = True
    opensearch_ca_cert: str | None = None
    opensearch_timeout: float = 15.0
    opensearch_max_retries: int = 3

    @field_validator("wazuh_api_url", "opensearch_url", mode="before")
    @classmethod
    def strip_trailing_slash(cls, v: str) -> str:
        return v.rstrip("/") if isinstance(v, str) else v

    @field_validator("soc_db_url", mode="before")
    @classmethod
    def validate_db_url(cls, v: str) -> str:
        if isinstance(v, str) and not v.startswith("postgresql"):
            raise ValueError("SOC_DB_URL must be a PostgreSQL connection string.")
        return v


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Return the cached singleton Settings instance."""
    return Settings()
