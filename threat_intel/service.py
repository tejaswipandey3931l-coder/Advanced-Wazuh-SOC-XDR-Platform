"""
Threat Intelligence Service: Orchestrates IOC extraction, normalization,
provider routing, Redis caching, bounded concurrency, consensus evaluation,
and append-only PostgreSQL persistence.
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone
from typing import Any, Sequence
import uuid

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload
import structlog

from backend.app.config import get_settings
from backend.app.models.incident import Incident
from backend.app.models.incident_event import IncidentEvent
from backend.app.models.normalized_event import NormalizedEvent
from backend.app.models.threat_intel_result import CTISource, IOCType, ThreatIntelResult
from threat_intel.cache import ThreatIntelCache
from threat_intel.consensus import ConsensusEngine
from threat_intel.extractor import IOCExtractor
from threat_intel.models import (
    EnrichedObservable,
    EnrichmentConsensus,
    NormalizedObservable,
    ProviderHealth,
    ProviderResult,
    ProviderStatus,
    ThreatVerdict,
)
from threat_intel.providers import ProviderRegistry, create_default_registry

logger = structlog.get_logger(__name__)


class ThreatIntelService:
    """
    Core orchestrator for Threat Intelligence Enrichment in Phase 4.
    Adheres to service-level bounded concurrency and append-only database semantics.
    """

    def __init__(
        self,
        registry: ProviderRegistry | None = None,
        cache: ThreatIntelCache | None = None,
        max_concurrent_lookups: int | None = None,
    ) -> None:
        cfg = get_settings()
        self.registry = registry or create_default_registry()
        self.cache = cache or ThreatIntelCache()
        limit = max_concurrent_lookups or cfg.ti_max_concurrent_lookups
        self._semaphore = asyncio.Semaphore(limit)

    async def _query_single_provider(
        self,
        provider_name: str,
        observable: NormalizedObservable,
        force_refresh: bool = False,
    ) -> ProviderResult:
        """Queries an individual provider with cache lookup and concurrency bounding."""
        provider = self.registry.get(provider_name)
        if not provider:
            return ProviderResult(
                provider=provider_name,
                observable=observable,
                status=ProviderStatus.NOT_FOUND,
                verdict=ThreatVerdict.UNKNOWN,
                error_message=f"Provider '{provider_name}' not registered",
            )

        # 1. Check cache if not force_refresh
        if not force_refresh:
            cached_result = await self.cache.get(provider_name, observable)
            if cached_result:
                logger.debug(
                    "ti_cache_hit",
                    provider=provider_name,
                    ioc_type=observable.ioc_type.value,
                    ioc_value=observable.canonical_value,
                )
                return cached_result

        # 2. Cache miss or forced refresh: execute query bounded by semaphore
        async with self._semaphore:
            logger.debug(
                "ti_provider_querying",
                provider=provider_name,
                ioc_type=observable.ioc_type.value,
                ioc_value=observable.canonical_value,
            )
            try:
                result = await provider.lookup(observable)
            except Exception as exc:
                logger.error("ti_provider_unhandled_exception", provider=provider_name, error=str(exc))
                result = ProviderResult(
                    provider=provider_name,
                    observable=observable,
                    status=ProviderStatus.NETWORK_ERROR,
                    verdict=ThreatVerdict.UNKNOWN,
                    error_message=f"Unhandled provider error: {exc}",
                )

        # 3. Cache the newly retrieved result
        await self.cache.set(provider_name, observable, result)
        return result

    async def enrich_observable(
        self,
        observable: NormalizedObservable,
        requested_providers: list[str] | None = None,
        force_refresh: bool = False,
        db: AsyncSession | None = None,
        event_id: uuid.UUID | None = None,
        incident_id: uuid.UUID | None = None,
    ) -> EnrichedObservable:
        """
        Enriches a single normalized observable across all applicable providers:
        - Filters providers according to observable routability (internal IPs query LocalFeed only)
        - Queries providers concurrently bounded by semaphore
        - Derives explainable consensus
        - Persists individual provider results to PostgreSQL using append-only semantics
        """
        applicable = self.registry.get_applicable_providers(observable, requested_providers)

        if not applicable:
            consensus = ConsensusEngine.evaluate(observable, [])
            return EnrichedObservable(
                observable=observable,
                consensus=consensus,
                provider_results=[],
            )

        # Query all applicable providers in parallel
        tasks = [
            self._query_single_provider(p.name, observable, force_refresh=force_refresh)
            for p in applicable
        ]
        results: list[ProviderResult] = await asyncio.gather(*tasks)

        # Derive consensus
        consensus = ConsensusEngine.evaluate(observable, results)

        # Persist provider evidence to database if session provided
        if db is not None:
            await self._persist_results(
                db=db,
                results=results,
                event_id=event_id,
                incident_id=incident_id,
            )

        return EnrichedObservable(
            observable=observable,
            consensus=consensus,
            provider_results=results,
        )

    async def enrich_observables(
        self,
        observables: Sequence[NormalizedObservable],
        requested_providers: list[str] | None = None,
        force_refresh: bool = False,
        db: AsyncSession | None = None,
        event_id: uuid.UUID | None = None,
        incident_id: uuid.UUID | None = None,
    ) -> list[EnrichedObservable]:
        """Enriches a batch of observables."""
        if not observables:
            return []

        tasks = [
            self.enrich_observable(
                obs,
                requested_providers=requested_providers,
                force_refresh=force_refresh,
                db=db,
                event_id=event_id,
                incident_id=incident_id,
            )
            for obs in observables
        ]
        return await asyncio.gather(*tasks)

    async def enrich_event(
        self,
        event_id: uuid.UUID,
        db: AsyncSession,
        requested_providers: list[str] | None = None,
        force_refresh: bool = False,
    ) -> list[EnrichedObservable]:
        """
        Extracts and enriches all observables from a NormalizedEvent.
        Links historical records to event_id.
        """
        stmt = select(NormalizedEvent).where(NormalizedEvent.id == event_id)
        res = await db.execute(stmt)
        event = res.scalar_one_or_none()
        if not event:
            raise ValueError(f"NormalizedEvent with ID '{event_id}' not found")

        observables = IOCExtractor.extract_from_event(event)
        if not observables:
            return []

        return await self.enrich_observables(
            observables=observables,
            requested_providers=requested_providers,
            force_refresh=force_refresh,
            db=db,
            event_id=event.id,
            incident_id=None,
        )

    async def enrich_incident(
        self,
        incident_id: uuid.UUID,
        db: AsyncSession,
        requested_providers: list[str] | None = None,
        force_refresh: bool = False,
    ) -> list[EnrichedObservable]:
        """
        Extracts and enriches all distinct observables across an Incident and member events.
        Links historical records to incident_id.
        """
        stmt = select(Incident).where(Incident.id == incident_id)
        res = await db.execute(stmt)
        incident = res.scalar_one_or_none()
        if not incident:
            raise ValueError(f"Incident with ID '{incident_id}' not found")

        # Load member events
        ev_stmt = (
            select(NormalizedEvent)
            .join(IncidentEvent, IncidentEvent.normalized_event_id == NormalizedEvent.id)
            .where(IncidentEvent.incident_id == incident_id)
        )
        ev_res = await db.execute(ev_stmt)
        member_events = list(ev_res.scalars().all())

        observables = IOCExtractor.extract_from_incident(incident, member_events)
        if not observables:
            return []

        results = await self.enrich_observables(
            observables=observables,
            requested_providers=requested_providers,
            force_refresh=force_refresh,
            db=db,
            event_id=None,
            incident_id=incident.id,
        )

        if results:
            incident.evidence_version = (incident.evidence_version or 1) + 1
            await db.flush()
            try:
                import asyncio
                from risk_engine.service import RiskService
                asyncio.create_task(
                    RiskService.evaluate_incident_background(
                        incident.id, trigger_reason="cti_enriched"
                    )
                )
            except Exception:
                pass

        return results

    async def _persist_results(
        self,
        db: AsyncSession,
        results: list[ProviderResult],
        event_id: uuid.UUID | None = None,
        incident_id: uuid.UUID | None = None,
    ) -> None:
        """
        Appends historical threat intelligence results to PostgreSQL.
        Strict application-layer append-only semantics:
        Every lookup creates a new row with its own ID; existing records are NEVER updated or deleted.
        """
        now = datetime.now(timezone.utc)

        for r in results:
            # Map provider name to CTISource enum
            try:
                source_enum = CTISource(r.provider.lower())
            except ValueError:
                # Fallback to local_feed if unknown provider name
                source_enum = CTISource.LOCAL_FEED

            matched = r.status == ProviderStatus.SUCCESS and r.verdict in (
                ThreatVerdict.MALICIOUS,
                ThreatVerdict.SUSPICIOUS,
            )

            ttl_seconds = self.cache.calculate_ttl(r)
            cache_expires = r.queried_at + timedelta(seconds=ttl_seconds)

            primary_threat_type = r.threat_types[0] if r.threat_types else None
            effective_conf = r.provider_confidence if r.provider_confidence is not None else r.derived_heuristic_confidence

            ti_row = ThreatIntelResult(
                id=uuid.uuid4(),
                normalized_event_id=event_id,
                incident_id=incident_id,
                ioc_type=r.observable.ioc_type,
                ioc_value=r.observable.canonical_value,
                source=source_enum,
                matched=matched,
                verdict=r.verdict.value,
                severity=r.severity.value if r.severity else None,
                confidence=effective_conf,
                provider_confidence=r.provider_confidence,
                derived_heuristic_confidence=r.derived_heuristic_confidence,
                threat_type=primary_threat_type,
                context=r.raw_payload,
                raw_response_text=r.raw_response_text,
                source_reference=r.source_reference,
                queried_at=r.queried_at,
                cache_expires_at=cache_expires,
                created_at=now,
                updated_at=now,
            )
            db.add(ti_row)

        await db.flush()

    async def invalidate_cache(
        self,
        provider: str | None = None,
        observable: NormalizedObservable | None = None,
        key_pattern: str | None = None,
    ) -> int:
        """Purges cache entries across Redis and fallback."""
        return await self.cache.invalidate(
            provider=provider,
            observable=observable,
            key_pattern=key_pattern,
        )

    async def check_health(self) -> dict[str, Any]:
        """Probes all providers and cache subsystem."""
        provider_healths: list[ProviderHealth] = []
        for p in self.registry.get_all():
            provider_healths.append(await p.check_health())

        cache_health = await self.cache.check_health()

        return {
            "status": "healthy" if cache_health.get("redis_connected") else "degraded",
            "cache": cache_health,
            "providers": [h.model_dump() for h in provider_healths],
        }

    async def close(self) -> None:
        """Closes all provider sessions and cache connections."""
        await self.registry.close_all()
        await self.cache.close()
