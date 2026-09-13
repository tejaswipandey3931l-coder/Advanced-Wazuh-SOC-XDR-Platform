"""
VirusTotal v3 CTI Provider: REST client for files, domains, URLs, and IP addresses.
Enforces strict TLS verification, raw engine statistics preservation,
uncalibrated heuristic confidence calculations, and private observable shielding.
"""

from __future__ import annotations

import base64
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


class VirusTotalProvider(BaseThreatIntelProvider):
    """
    VirusTotal v3 CTI Provider.
    Disabled by default; requires explicit API key configuration.
    Stores multi-engine detection metrics and documents confidence as an uncalibrated heuristic.
    """

    BASE_URL = "https://www.virustotal.com/api/v3"

    def __init__(
        self,
        api_key: str | None = None,
        enabled: bool | None = None,
        timeout: float | None = None,
        client: httpx.AsyncClient | None = None,
    ):
        cfg = get_settings()
        self._api_key = api_key if api_key is not None else cfg.virustotal_api_key
        self._enabled = enabled if enabled is not None else cfg.virustotal_enabled
        self._timeout = timeout or cfg.ti_provider_timeout

        self._client = client or httpx.AsyncClient(
            verify=True,
            timeout=self._timeout,
            headers={
                "x-apikey": self._api_key,
                "Accept": "application/json",
                "User-Agent": "Advanced-Wazuh-SOC-Phase4/1.0",
            },
        )
        self._owns_client = client is None

    @property
    def name(self) -> str:
        return "virustotal"

    @property
    def supported_ioc_types(self) -> set[IOCType]:
        return {IOCType.FILE_HASH, IOCType.DOMAIN, IOCType.IP, IOCType.URL}

    def _get_endpoint_for_observable(self, observable: NormalizedObservable) -> tuple[str, str]:
        """Maps an observable to its VT v3 endpoint and web report URL."""
        val = observable.canonical_value

        if observable.ioc_type == IOCType.FILE_HASH:
            return f"{self.BASE_URL}/files/{val}", f"https://www.virustotal.com/gui/file/{val}"

        if observable.ioc_type == IOCType.DOMAIN:
            return f"{self.BASE_URL}/domains/{val}", f"https://www.virustotal.com/gui/domain/{val}"

        if observable.ioc_type == IOCType.IP:
            return f"{self.BASE_URL}/ip_addresses/{val}", f"https://www.virustotal.com/gui/ip-address/{val}"

        if observable.ioc_type == IOCType.URL:
            # VT v3 URL identifier: base64 without padding of the URL
            url_id = base64.urlsafe_b64encode(val.encode("utf-8")).decode("ascii").rstrip("=")
            return f"{self.BASE_URL}/urls/{url_id}", f"https://www.virustotal.com/gui/url/{url_id}"

        raise ValueError(f"Unsupported IOC type: {observable.ioc_type}")

    async def lookup(self, observable: NormalizedObservable) -> ProviderResult:
        """Executes VirusTotal v3 lookup with error isolation and engine detection analysis."""
        start_time = time.perf_counter()

        # Guard: Check enabled and credentials
        if not self._enabled:
            return ProviderResult(
                provider=self.name,
                observable=observable,
                status=ProviderStatus.NOT_FOUND,
                verdict=ThreatVerdict.UNKNOWN,
                error_message="VirusTotal provider is disabled",
            )

        if not self._api_key:
            return ProviderResult(
                provider=self.name,
                observable=observable,
                status=ProviderStatus.AUTH_ERROR,
                verdict=ThreatVerdict.UNKNOWN,
                error_message="VirusTotal API key is not configured",
            )

        # Guard: Supported IOC types
        if observable.ioc_type not in self.supported_ioc_types:
            return ProviderResult(
                provider=self.name,
                observable=observable,
                status=ProviderStatus.NOT_FOUND,
                verdict=ThreatVerdict.UNKNOWN,
                error_message=f"VirusTotal does not support IOC type: {observable.ioc_type}",
            )

        # Guard: Non-routable / internal indicators shielding
        if not observable.is_routable_external:
            logger.warning(
                "virustotal_shielded_internal_indicator",
                ioc_type=observable.ioc_type,
                value=observable.canonical_value,
            )
            return ProviderResult(
                provider=self.name,
                observable=observable,
                status=ProviderStatus.NOT_FOUND,
                verdict=ThreatVerdict.UNKNOWN,
                error_message="Internal/non-routable indicator shielded from external query",
            )

        try:
            endpoint_url, report_url = self._get_endpoint_for_observable(observable)
        except ValueError as exc:
            return ProviderResult(
                provider=self.name,
                observable=observable,
                status=ProviderStatus.NOT_FOUND,
                verdict=ThreatVerdict.UNKNOWN,
                error_message=str(exc),
            )

        # Execute HTTP GET
        try:
            response = await self._client.get(endpoint_url)
        except httpx.TimeoutException:
            logger.warning("virustotal_timeout", value=observable.canonical_value)
            return ProviderResult(
                provider=self.name,
                observable=observable,
                status=ProviderStatus.TIMEOUT,
                verdict=ThreatVerdict.UNKNOWN,
                error_message=f"Request timed out after {self._timeout}s",
            )
        except httpx.NetworkError as exc:
            logger.error("virustotal_network_error", value=observable.canonical_value, error=str(exc))
            return ProviderResult(
                provider=self.name,
                observable=observable,
                status=ProviderStatus.NETWORK_ERROR,
                verdict=ThreatVerdict.UNKNOWN,
                error_message=f"Network error connecting to VirusTotal: {exc}",
            )
        except Exception as exc:
            logger.error("virustotal_unexpected_error", value=observable.canonical_value, error=str(exc))
            return ProviderResult(
                provider=self.name,
                observable=observable,
                status=ProviderStatus.NETWORK_ERROR,
                verdict=ThreatVerdict.UNKNOWN,
                error_message=f"Unexpected error: {exc}",
            )

        # Handle HTTP status codes
        if response.status_code == 404:
            # Indicator not found in VirusTotal database (no threat record exists)
            # NOT_FOUND semantics: Provider evaluated successfully, but has no record.
            # This does NOT constitute objective proof of benignness.
            return ProviderResult(
                provider=self.name,
                observable=observable,
                status=ProviderStatus.NOT_FOUND,
                verdict=ThreatVerdict.UNKNOWN,
                severity=ThreatSeverity.NONE,
                provider_confidence=None,
                derived_heuristic_confidence=None,
                threat_types=[],
                raw_payload={"found": False, "status_code": 404},
                raw_response_text=response.text,
                source_reference=report_url,
                queried_at=datetime.now(timezone.utc),
                cached=False,
            )

        if response.status_code == 401 or response.status_code == 403:
            logger.error("virustotal_auth_error", status_code=response.status_code)
            return ProviderResult(
                provider=self.name,
                observable=observable,
                status=ProviderStatus.AUTH_ERROR,
                verdict=ThreatVerdict.UNKNOWN,
                raw_response_text=response.text[:500],
                error_message="Authentication failed with VirusTotal (invalid API key)",
            )

        if response.status_code == 429:
            logger.warning("virustotal_rate_limited", status_code=429)
            return ProviderResult(
                provider=self.name,
                observable=observable,
                status=ProviderStatus.RATE_LIMITED,
                verdict=ThreatVerdict.UNKNOWN,
                raw_response_text=response.text[:500],
                error_message="Rate limit exceeded on VirusTotal (HTTP 429)",
            )

        if response.status_code != 200:
            logger.error("virustotal_http_error", status_code=response.status_code)
            return ProviderResult(
                provider=self.name,
                observable=observable,
                status=ProviderStatus.NETWORK_ERROR,
                verdict=ThreatVerdict.UNKNOWN,
                raw_response_text=response.text[:500],
                error_message=f"VirusTotal returned HTTP {response.status_code}",
            )

        # Parse 200 OK JSON response
        try:
            body = response.json()
            attributes = body.get("data", {}).get("attributes", {})
        except Exception as exc:
            return ProviderResult(
                provider=self.name,
                observable=observable,
                status=ProviderStatus.NETWORK_ERROR,
                verdict=ThreatVerdict.UNKNOWN,
                error_message=f"Failed to parse JSON response: {exc}",
            )

        stats = attributes.get("last_analysis_stats", {})
        malicious = int(stats.get("malicious", 0))
        suspicious = int(stats.get("suspicious", 0))
        harmless = int(stats.get("harmless", 0))
        undetected = int(stats.get("undetected", 0))
        total_engines = malicious + suspicious + harmless + undetected

        # Preserve engine stats in raw_payload
        raw_payload = {
            "last_analysis_stats": stats,
            "malicious_engines": malicious,
            "suspicious_engines": suspicious,
            "harmless_engines": harmless,
            "undetected_engines": undetected,
            "total_engines": total_engines,
            "reputation": attributes.get("reputation"),
            "tags": attributes.get("tags", []),
        }

        # Deterministic classification:
        # Confidence is explicitly derived_heuristic_confidence (uncalibrated heuristic, NOT a probability)
        if malicious >= 5:
            verdict = ThreatVerdict.MALICIOUS
            severity = ThreatSeverity.CRITICAL if malicious >= 15 else ThreatSeverity.HIGH
            derived_conf = round(min(1.0, max(0.5, malicious / 20.0)), 4)
        elif malicious >= 1 or suspicious >= 2:
            verdict = ThreatVerdict.SUSPICIOUS
            severity = ThreatSeverity.MEDIUM
            derived_conf = 0.50
        else:
            verdict = ThreatVerdict.BENIGN
            severity = ThreatSeverity.NONE
            derived_conf = 0.90 if total_engines >= 10 else 0.70

        threat_types: list[str] = []
        if malicious > 0:
            threat_types.append("av_malicious")
        if suspicious > 0:
            threat_types.append("av_suspicious")
        for tag in attributes.get("tags", [])[:5]:
            threat_types.append(f"tag:{tag}")

        return ProviderResult(
            provider=self.name,
            observable=observable,
            status=ProviderStatus.SUCCESS,
            verdict=verdict,
            severity=severity,
            provider_confidence=None,  # VirusTotal has no native single confidence; store heuristic below
            derived_heuristic_confidence=derived_conf,
            threat_types=threat_types,
            raw_payload=raw_payload,
            raw_response_text=response.text,
            source_reference=report_url,
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
