"""
Threat Intelligence Provider Registry and Factory.
"""

from __future__ import annotations

from typing import Iterable

from backend.app.models.threat_intel_result import IOCType
from threat_intel.models import NormalizedObservable
from threat_intel.providers.abuseipdb import AbuseIPDBProvider
from threat_intel.providers.base import BaseThreatIntelProvider
from threat_intel.providers.local_feed import LocalFeedProvider
from threat_intel.providers.virustotal import VirusTotalProvider


class ProviderRegistry:
    """Registry managing active CTI provider instances."""

    def __init__(self, providers: Iterable[BaseThreatIntelProvider] | None = None):
        self._providers: dict[str, BaseThreatIntelProvider] = {}
        if providers:
            for p in providers:
                self.register(p)

    def register(self, provider: BaseThreatIntelProvider) -> None:
        """Registers a provider instance."""
        self._providers[provider.name] = provider

    def get(self, name: str) -> BaseThreatIntelProvider | None:
        """Retrieves a provider by name."""
        return self._providers.get(name)

    def get_all(self) -> list[BaseThreatIntelProvider]:
        """Returns all registered providers."""
        return list(self._providers.values())

    def get_applicable_providers(
        self,
        observable: NormalizedObservable,
        requested_providers: list[str] | None = None,
    ) -> list[BaseThreatIntelProvider]:
        """
        Determines which providers to query for an observable:
        - If internal/non-routable, returns ONLY local_feed!
        - If requested_providers specified, filters to those requested.
        - Filters to providers that support the observable's IOC type.
        """
        applicable: list[BaseThreatIntelProvider] = []

        for name, provider in self._providers.items():
            if requested_providers and name not in requested_providers:
                continue

            # Strict External Disclosure Shielding:
            # Internal/non-routable indicators MUST NEVER be queried against external providers!
            if not observable.is_routable_external and name != "local_feed":
                continue

            if observable.ioc_type in provider.supported_ioc_types:
                applicable.append(provider)

        return applicable

    async def close_all(self) -> None:
        """Closes all provider client sessions."""
        for provider in self._providers.values():
            await provider.close()


def create_default_registry() -> ProviderRegistry:
    """Factory creating the default V1 provider registry."""
    registry = ProviderRegistry()
    registry.register(LocalFeedProvider())
    registry.register(AbuseIPDBProvider())
    registry.register(VirusTotalProvider())
    return registry


__all__ = [
    "BaseThreatIntelProvider",
    "LocalFeedProvider",
    "AbuseIPDBProvider",
    "VirusTotalProvider",
    "ProviderRegistry",
    "create_default_registry",
]
