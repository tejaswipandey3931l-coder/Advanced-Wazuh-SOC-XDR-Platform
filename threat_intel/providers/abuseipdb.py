"""
AbuseIPDB v2 CTI Provider: REST client for IPv4/IPv6 abuse confidence lookups.
Enforces strict TLS verification, timeout handling, rate limit handling,
and private IP shielding.
"""

from __future__ import annotations

from datetime import datetime, timezone
import time
from typing import Any

import httpx
import structlog

from backend.app.config import get_settings
from backend.app.models.threat_intel_result import IOCType
from threat_intel.models import (
    NormalizedObservable,
    ProviderHealth,
    ProviderResult,
    ProviderStatus,
    ThreatSeverity,
    ThreatVerdict,
)
from threat_intel.providers.base import BaseThreatIntelProvider

logger = structlog.get_logger(__name__)


class AbuseIPDBProvider(BaseThreatIntelProvider):
    """
    AbuseIPDB v2 CTI Provider.
    Disabled by default; requires explicit API key configuration.
    Never transmits private/internal indicators.
    """

    BASE_URL = "https://api.abuseipdb.com/api/v2"

    def __init__(
        self,
        api_key: str | None = None,
        enabled: bool | None = None,
        timeout: float | None = None,
        client: httpx.AsyncClient | None = None,
    ):
        cfg = get_settings()
        self._api_key = api_key if api_key is not None else cfg.abuseipdb_api_key
        self._enabled = enabled if enabled is not None else cfg.abuseipdb_enabled
        self._timeout = timeout or cfg.ti_provider_timeout

        # Reusable client with strict TLS verification
        self._client = client or httpx.AsyncClient(
            verify=True,
            timeout=self._timeout,
            headers={
                "Key": self._api_key,
                "Accept": "application/json",
                "User-Agent": "Advanced-Wazuh-SOC-Phase4/1.0",
            },
        )
        self._owns_client = client is None

    @property
    def name(self) -> str:
        return "abuseipdb"

    @property
    def supported_ioc_types(self) -> set[IOCType]:
        return {IOCType.IP}

    async def lookup(self, observable: NormalizedObservable) -> ProviderResult:
        """Queries AbuseIPDB check endpoint for public IP observables."""
        start_time = time.perf_counter()

        # Guard: Check enabled and credentials
        if not self._enabled:
            return ProviderResult(
                provider=self.name,
                observable=observable,
                status=ProviderStatus.NOT_FOUND,
                verdict=ThreatVerdict.UNKNOWN,
                error_message="AbuseIPDB provider is disabled",
            )

        if not self._api_key:
            return ProviderResult(
                provider=self.name,
                observable=observable,
                status=ProviderStatus.AUTH_ERROR,
                verdict=ThreatVerdict.UNKNOWN,
                error_message="AbuseIPDB API key is not configured",
            )

        # Guard: IOC type must be IP
        if observable.ioc_type != IOCType.IP:
            return ProviderResult(
                provider=self.name,
                observable=observable,
                status=ProviderStatus.NOT_FOUND,
                verdict=ThreatVerdict.UNKNOWN,
                error_message=f"AbuseIPDB does not support IOC type: {observable.ioc_type}",
            )

        # Guard: Private/internal IP shielding - NEVER query external CTI for non-routable IPs!
        if not observable.is_routable_external:
            logger.warning(
                "abuseipdb_shielded_internal_ip",
                ip=observable.canonical_value,
                classification=observable.ip_classification,
            )
            return ProviderResult(
                provider=self.name,
                observable=observable,
                status=ProviderStatus.NOT_FOUND,
                verdict=ThreatVerdict.UNKNOWN,
                error_message="Internal/non-routable IP address shielded from external query",
            )

        # Execute HTTP lookup
        url = f"{self.BASE_URL}/check"
        params = {
            "ipAddress": observable.canonical_value,
            "maxAgeInDays": "90",
            "verbose": "",
        }

        try:
            response = await self._client.get(url, params=params)
        except httpx.TimeoutException:
            logger.warning("abuseipdb_timeout", ip=observable.canonical_value)
            return ProviderResult(
                provider=self.name,
                observable=observable,
                status=ProviderStatus.TIMEOUT,
                verdict=ThreatVerdict.UNKNOWN,
                error_message=f"Request timed out after {self._timeout}s",
            )
        except httpx.NetworkError as exc:
            logger.error("abuseipdb_network_error", ip=observable.canonical_value, error=str(exc))
            return ProviderResult(
                provider=self.name,
                observable=observable,
                status=ProviderStatus.NETWORK_ERROR,
                verdict=ThreatVerdict.UNKNOWN,
                error_message=f"Network error connecting to AbuseIPDB: {exc}",
            )
        except Exception as exc:
            logger.error("abuseipdb_unexpected_error", ip=observable.canonical_value, error=str(exc))
            return ProviderResult(
                provider=self.name,
                observable=observable,
                status=ProviderStatus.NETWORK_ERROR,
                verdict=ThreatVerdict.UNKNOWN,
                error_message=f"Unexpected error: {exc}",
            )

        # Handle HTTP status codes
        if response.status_code == 401 or response.status_code == 403:
            logger.error("abuseipdb_auth_error", status_code=response.status_code)
            return ProviderResult(
                provider=self.name,
                observable=observable,
                status=ProviderStatus.AUTH_ERROR,
                verdict=ThreatVerdict.UNKNOWN,
                raw_response_text=response.text[:500],
                error_message="Authentication failed with AbuseIPDB (invalid API key)",
            )

        if response.status_code == 429:
            logger.warning("abuseipdb_rate_limited", status_code=429)
            return ProviderResult(
                provider=self.name,
                observable=observable,
                status=ProviderStatus.RATE_LIMITED,
                verdict=ThreatVerdict.UNKNOWN,
                raw_response_text=response.text[:500],
                error_message="Rate limit exceeded on AbuseIPDB (HTTP 429)",
            )

        if response.status_code != 200:
            logger.error("abuseipdb_http_error", status_code=response.status_code, body=response.text[:200])
            return ProviderResult(
                provider=self.name,
                observable=observable,
                status=ProviderStatus.NETWORK_ERROR,
                verdict=ThreatVerdict.UNKNOWN,
                raw_response_text=response.text[:500],
                error_message=f"AbuseIPDB returned HTTP {response.status_code}",
            )

        # Parse 200 OK JSON response
        try:
            data = response.json().get("data", {})
        except Exception as exc:
            return ProviderResult(
                provider=self.name,
                observable=observable,
                status=ProviderStatus.NETWORK_ERROR,
                verdict=ThreatVerdict.UNKNOWN,
                error_message=f"Failed to parse JSON response: {exc}",
            )

        abuse_score = float(data.get("abuseConfidenceScore", 0))
        total_reports = int(data.get("totalReports", 0))
        native_confidence = min(1.0, max(0.0, abuse_score / 100.0))

        # Check for clean / not found condition
        # If isWhitelisted is True, AbuseIPDB provides explicit clean evidence.
        if data.get("isWhitelisted") is True:
            return ProviderResult(
                provider=self.name,
                observable=observable,
                status=ProviderStatus.SUCCESS,
                verdict=ThreatVerdict.BENIGN,
                severity=ThreatSeverity.NONE,
                provider_confidence=1.0,  # Whitelisted IP confirmed clean by provider
                derived_heuristic_confidence=None,
                threat_types=["whitelisted"],
                raw_payload=data,
                raw_response_text=response.text,
                source_reference=f"https://www.abuseipdb.com/check/{observable.canonical_value}",
                queried_at=datetime.now(timezone.utc),
                cached=False,
            )

        # If zero reports and zero score, provider has no abuse record for this IP.
        # NOT_FOUND semantics: Evaluated successfully, but no threat record exists.
        # This is NOT proof of objective benignness.
        if abuse_score == 0 and total_reports == 0:
            return ProviderResult(
                provider=self.name,
                observable=observable,
                status=ProviderStatus.NOT_FOUND,
                verdict=ThreatVerdict.UNKNOWN,
                severity=ThreatSeverity.NONE,
                provider_confidence=None,
                derived_heuristic_confidence=None,
                threat_types=[],
                raw_payload=data,
                raw_response_text=response.text,
                source_reference=f"https://www.abuseipdb.com/check/{observable.canonical_value}",
                queried_at=datetime.now(timezone.utc),
                cached=False,
            )

        # Categorize verdict based on abuse confidence score and report count
        if abuse_score >= 75 or total_reports >= 20:
            verdict = ThreatVerdict.MALICIOUS
            severity = ThreatSeverity.CRITICAL if abuse_score >= 90 else ThreatSeverity.HIGH
        elif abuse_score >= 25 or total_reports >= 5:
            verdict = ThreatVerdict.SUSPICIOUS
            severity = ThreatSeverity.MEDIUM
        else:
            verdict = ThreatVerdict.BENIGN
            severity = ThreatSeverity.LOW
            native_confidence = 1.0 - native_confidence

        threat_types = ["ip_abuse"]
        if data.get("usageType"):
            threat_types.append(f"usage:{data['usageType'].lower()}")

        return ProviderResult(
            provider=self.name,
            observable=observable,
            status=ProviderStatus.SUCCESS,
            verdict=verdict,
            severity=severity,
            provider_confidence=round(native_confidence, 4),
            derived_heuristic_confidence=None,  # AbuseIPDB reports native confidence
            threat_types=threat_types,
            raw_payload=data,
            raw_response_text=response.text,
            source_reference=f"https://www.abuseipdb.com/check/{observable.canonical_value}",
            queried_at=datetime.now(timezone.utc),
            cached=False,
        )

    async def check_health(self) -> ProviderHealth:
        """Checks whether provider is configured and reachable."""
        if not self._enabled:
            return ProviderHealth(
                provider=self.name,
                status="disabled",
                enabled=False,
                checked_at=datetime.now(timezone.utc),
            )

        if not self._api_key:
            return ProviderHealth(
                provider=self.name,
                status="unhealthy",
                enabled=True,
                error_message="API key missing",
                checked_at=datetime.now(timezone.utc),
            )

        return ProviderHealth(
            provider=self.name,
            status="healthy",
            enabled=True,
            checked_at=datetime.now(timezone.utc),
        )

    async def close(self) -> None:
        """Closes internal HTTP client if owned."""
        if self._owns_client and self._client:
            await self._client.aclose()
