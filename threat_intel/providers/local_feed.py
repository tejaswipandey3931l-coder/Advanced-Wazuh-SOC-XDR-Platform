"""
Local Feed CTI Provider: High-speed, in-memory indicator lookup
supporting exact matches, CIDR subnets, and domain wildcards.
"""

from __future__ import annotations

from datetime import datetime, timezone
import ipaddress
import json
import os
import time
from typing import Any

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


class LocalFeedProvider(BaseThreatIntelProvider):
    """
    In-memory CTI provider matching indicators against local configuration feeds.
    Zero external network calls; thread-safe read operations.
    """

    def __init__(self, feed_path: str | None = None, enabled: bool | None = None):
        cfg = get_settings()
        self._feed_path = feed_path or cfg.ti_local_feed_path
        self._enabled = enabled if enabled is not None else cfg.ti_local_feed_enabled

        # In-memory lookup tables
        self._exact_indicators: dict[tuple[IOCType, str], dict[str, Any]] = {}
        self._ip_networks: list[tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, dict[str, Any]]] = []
        self._domain_wildcards: list[tuple[str, dict[str, Any]]] = []
        self._loaded_at: datetime | None = None
        self._indicator_count = 0

        self.load_feed()

    @property
    def name(self) -> str:
        return "local_feed"

    @property
    def supported_ioc_types(self) -> set[IOCType]:
        return {IOCType.IP, IOCType.DOMAIN, IOCType.URL, IOCType.FILE_HASH, IOCType.EMAIL}

    def load_feed(self) -> None:
        """Loads and parses indicators from the local feed JSON file."""
        if not self._enabled:
            logger.info("local_feed_disabled", path=self._feed_path)
            return

        if not os.path.exists(self._feed_path):
            logger.warning("local_feed_file_not_found", path=self._feed_path)
            return

        try:
            with open(self._feed_path, "r", encoding="utf-8") as f:
                data = json.load(f)

            indicators = data.get("indicators", [])
            exact_map: dict[tuple[IOCType, str], dict[str, Any]] = {}
            networks: list[tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, dict[str, Any]]] = []
            wildcards: list[tuple[str, dict[str, Any]]] = []

            for item in indicators:
                raw_type = item.get("ioc_type", "").lower()
                raw_val = item.get("value", "").strip()
                if not raw_type or not raw_val:
                    continue

                try:
                    ioc_type = IOCType(raw_type)
                except ValueError:
                    continue

                # IP CIDR check
                if ioc_type == IOCType.IP and "/" in raw_val:
                    try:
                        net = ipaddress.ip_network(raw_val, strict=False)
                        networks.append((net, item))
                        continue
                    except ValueError:
                        pass

                # Domain wildcard check
                if ioc_type == IOCType.DOMAIN and raw_val.startswith("*."):
                    suffix = raw_val[2:].lower().strip(".")
                    wildcards.append((suffix, item))
                    continue

                # Exact canonical match
                canon_val = raw_val.lower()
                exact_map[(ioc_type, canon_val)] = item

            self._exact_indicators = exact_map
            self._ip_networks = networks
            self._domain_wildcards = wildcards
            self._indicator_count = len(indicators)
            self._loaded_at = datetime.now(timezone.utc)

            logger.info(
                "local_feed_loaded",
                path=self._feed_path,
                count=self._indicator_count,
                exact_count=len(exact_map),
                network_count=len(networks),
                wildcard_count=len(wildcards),
            )
        except Exception as e:
            logger.error("local_feed_load_failed", path=self._feed_path, error=str(e))

    def _find_match(self, observable: NormalizedObservable) -> dict[str, Any] | None:
        """Performs exact, CIDR, or wildcard match for an observable."""
        canon = observable.canonical_value.lower()

        # 1. Exact match
        exact_key = (observable.ioc_type, canon)
        if exact_key in self._exact_indicators:
            return self._exact_indicators[exact_key]

        # 2. IP CIDR match
        if observable.ioc_type == IOCType.IP:
            try:
                ip_obj = ipaddress.ip_address(canon)
                for net, item in self._ip_networks:
                    if ip_obj in net:
                        return item
            except ValueError:
                pass

        # 3. Domain wildcard / subdomain match
        if observable.ioc_type == IOCType.DOMAIN:
            for suffix, item in self._domain_wildcards:
                if canon == suffix or canon.endswith("." + suffix):
                    return item

        return None

    async def lookup(self, observable: NormalizedObservable) -> ProviderResult:
        """Matches observable against in-memory feed."""
        start_time = time.perf_counter()

        if not self._enabled:
            return ProviderResult(
                provider=self.name,
                observable=observable,
                status=ProviderStatus.NOT_FOUND,
                verdict=ThreatVerdict.UNKNOWN,
                error_message="Provider is disabled",
            )

        if observable.ioc_type not in self.supported_ioc_types:
            return ProviderResult(
                provider=self.name,
                observable=observable,
                status=ProviderStatus.NOT_FOUND,
                verdict=ThreatVerdict.UNKNOWN,
                error_message=f"Unsupported IOC type: {observable.ioc_type}",
            )

        item = self._find_match(observable)
        elapsed_ms = (time.perf_counter() - start_time) * 1000.0

        if item:
            raw_verdict = item.get("verdict", "malicious").lower()
            try:
                verdict = ThreatVerdict(raw_verdict)
            except ValueError:
                verdict = ThreatVerdict.MALICIOUS

            raw_severity = item.get("severity")
            severity = ThreatSeverity(raw_severity.lower()) if raw_severity else None
            confidence = float(item.get("confidence", 1.0))

            return ProviderResult(
                provider=self.name,
                observable=observable,
                status=ProviderStatus.SUCCESS,
                verdict=verdict,
                severity=severity,
                provider_confidence=confidence,
                derived_heuristic_confidence=None,
                threat_types=list(item.get("threat_types", [])),
                raw_payload=item,
                source_reference=item.get("source_reference"),
                queried_at=datetime.now(timezone.utc),
                cached=False,
            )

        # Not found in local feed
        # NOT_FOUND semantics: Successfully evaluated against the local feed, but no record exists.
        # Absence of a record in the local feed does NOT objectively prove an indicator is benign.
        return ProviderResult(
            provider=self.name,
            observable=observable,
            status=ProviderStatus.NOT_FOUND,
            verdict=ThreatVerdict.UNKNOWN,
            severity=ThreatSeverity.NONE,
            provider_confidence=None,
            derived_heuristic_confidence=None,
            threat_types=[],
            raw_payload={"matched": False, "reason": "not_in_local_feed"},
            source_reference=None,
            queried_at=datetime.now(timezone.utc),
            cached=False,
        )

    async def check_health(self) -> ProviderHealth:
        """Probes local feed availability and indicator count."""
        start_time = time.perf_counter()

        if not self._enabled:
            return ProviderHealth(
                provider=self.name,
                status="disabled",
                enabled=False,
                checked_at=datetime.now(timezone.utc),
            )

        if not os.path.exists(self._feed_path):
            return ProviderHealth(
                provider=self.name,
                status="unhealthy",
                enabled=True,
                error_message=f"Feed file not found: {self._feed_path}",
                checked_at=datetime.now(timezone.utc),
            )

        elapsed_ms = (time.perf_counter() - start_time) * 1000.0
        return ProviderHealth(
            provider=self.name,
            status="healthy",
            enabled=True,
            latency_ms=round(elapsed_ms, 3),
            error_message=None,
            checked_at=datetime.now(timezone.utc),
        )

    async def close(self) -> None:
        """No external connections to close."""
        pass
