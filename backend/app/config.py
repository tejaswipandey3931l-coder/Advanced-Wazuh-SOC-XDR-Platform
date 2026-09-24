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

    # ── Threat Intelligence Settings (Phase 4) ──────────────────────────────
    ti_cache_ttl_positive: int = 86400   # 24 hours
    ti_cache_ttl_negative: int = 7200    # 2 hours
    ti_cache_ttl_error: int = 120        # 2 minutes
    ti_provider_timeout: float = 5.0     # 5.0 seconds
    ti_max_concurrent_lookups: int = 10  # Option A bounded concurrency
    ti_max_batch_size: int = 25          # Maximum observables per ad-hoc request
    ti_admin_token: str = ""             # Token for admin auth hook

    # Local Feed (V1 Mandatory)
    ti_local_feed_enabled: bool = True
    ti_local_feed_path: str = "configs/threat_intel/local_feed.json"

    # AbuseIPDB (V1 Mandatory - Disabled by default)
    abuseipdb_enabled: bool = False
    abuseipdb_api_key: str = ""
    abuseipdb_rate_limit_per_minute: int = 60
    abuseipdb_daily_quota: int = 1000  # Configured plan-specific daily quota limit (default represents observed free/public tier baseline at development time)

    # VirusTotal (V1 Mandatory - Disabled by default)
    virustotal_enabled: bool = False
    virustotal_api_key: str = ""
    virustotal_rate_limit_per_minute: int = 4
    virustotal_daily_quota: int = 500  # Configured plan-specific daily quota limit (default represents observed free/public tier baseline at development time)

    # Future Provider Adapters (Configuration hooks only)
    misp_enabled: bool = False
    misp_url: str = ""
    misp_api_key: str = ""
    misp_verify_ssl: bool = True

    opencti_enabled: bool = False
    opencti_url: str = ""
    opencti_token: str = ""
    opencti_verify_ssl: bool = True

    alienvault_otx_enabled: bool = False
    alienvault_otx_api_key: str = ""

    # ── Risk Engine Settings (Phase 5) ────────────────────────────────────────
    risk_enabled: bool = True
    risk_half_life_hours: float = 24.0
    risk_min_decay: float = 0.25
    risk_weight_severity: float = 0.30
    risk_weight_correlation: float = 0.25
    risk_weight_cti: float = 0.20
    risk_weight_volume: float = 0.10
    risk_weight_mitre: float = 0.15
    risk_clean_mitigation: float = 15.0
    risk_volume_ceiling: float = 90.0

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
