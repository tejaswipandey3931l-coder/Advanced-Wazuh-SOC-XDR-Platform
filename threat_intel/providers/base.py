"""
Abstract Base Provider for Cyber Threat Intelligence (CTI).
"""

from __future__ import annotations

from abc import ABC, abstractmethod

from backend.app.models.threat_intel_result import IOCType
from threat_intel.models import NormalizedObservable, ProviderHealth, ProviderResult


class BaseThreatIntelProvider(ABC):
    """
    Abstract interface contract for all CTI providers.
    Ensures decoupled, extensible integration of heterogeneous threat feeds.
    """

    @property
    @abstractmethod
    def name(self) -> str:
        """Unique provider identifier (e.g. 'local_feed', 'abuseipdb', 'virustotal')."""
        ...

    @property
    @abstractmethod
    def supported_ioc_types(self) -> set[IOCType]:
        """Set of observable types supported by this provider."""
        ...

    @abstractmethod
    async def lookup(self, observable: NormalizedObservable) -> ProviderResult:
        """
        Executes lookup for a single observable.
        Must return a structured ProviderResult and never raise unhandled network exceptions.
        Explicitly distinguishes: SUCCESS, NOT_FOUND, RATE_LIMITED, TIMEOUT, AUTH_ERROR, NETWORK_ERROR.
        """
        ...

    @abstractmethod
    async def check_health(self) -> ProviderHealth:
        """Probes provider availability, latency, and credential validity."""
        ...

    @abstractmethod
    async def close(self) -> None:
        """Cleans up internal connection pools and client sessions."""
        ...
