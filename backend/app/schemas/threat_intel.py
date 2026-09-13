"""
Pydantic v2 schemas for Threat Intelligence Enrichment REST endpoints.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any
import uuid

from pydantic import BaseModel, ConfigDict, Field

from backend.app.models.threat_intel_result import CTISource, IOCType
from threat_intel.models import (
    EnrichedObservable,
    EnrichmentConsensus,
    NormalizedObservable,
    ProviderResult,
)


class ObservableInput(BaseModel):
    """Input observable for ad-hoc enrichment."""

    ioc_value: str = Field(..., description="Observable indicator value (IP, domain, hash, URL, email)")
    ioc_type: str | None = Field(default=None, description="Optional indicator type ('ip', 'domain', 'url', 'file_hash', 'email')")


class EnrichmentRequest(BaseModel):
    """Request payload for ad-hoc enrichment."""

    observables: list[ObservableInput] = Field(
        ...,
        min_length=1,
        description="List of observables to enrich (maximum 25 items)",
    )
    providers: list[str] | None = Field(
        default=None,
        description="Optional list of provider names to query (e.g. ['local_feed', 'abuseipdb'])",
    )
    force_refresh: bool = Field(
        default=False,
        description="Bypass cache and force upstream query (requires admin authorization)",
    )


class ProviderResultSchema(BaseModel):
    """Serialized provider result."""

    provider: str
    ioc_type: str
    raw_value: str
    canonical_value: str
    status: str
    verdict: str
    severity: str | None = None
    provider_confidence: float | None = None
    derived_heuristic_confidence: float | None = None
    threat_types: list[str] = Field(default_factory=list)
    raw_payload: dict[str, Any] = Field(default_factory=dict)
    source_reference: str | None = None
    queried_at: datetime
    cached: bool = False
    error_message: str | None = None

    @classmethod
    def from_domain(cls, res: ProviderResult) -> ProviderResultSchema:
        return cls(
            provider=res.provider,
            ioc_type=res.observable.ioc_type.value,
            raw_value=res.observable.raw_value,
            canonical_value=res.observable.canonical_value,
            status=res.status.value,
            verdict=res.verdict.value,
            severity=res.severity.value if res.severity else None,
            provider_confidence=res.provider_confidence,
            derived_heuristic_confidence=res.derived_heuristic_confidence,
            threat_types=res.threat_types,
            raw_payload=res.raw_payload,
            source_reference=res.source_reference,
            queried_at=res.queried_at,
            cached=res.cached,
            error_message=res.error_message,
        )


class ConsensusSchema(BaseModel):
    """Serialized consensus evaluation."""

    verdict: str
    provider_confidence: float | None = None
    derived_heuristic_confidence: float | None = None
    severity: str | None = None
    providers_evaluated: list[str] = Field(default_factory=list)
    failed_providers: list[str] = Field(default_factory=list)
    agreeing_providers: list[str] = Field(default_factory=list)
    conflicting_providers: list[str] = Field(default_factory=list)
    rationale: str
    is_derived: bool = True

    @classmethod
    def from_domain(cls, c: EnrichmentConsensus) -> ConsensusSchema:
        return cls(
            verdict=c.verdict.value,
            provider_confidence=c.provider_confidence,
            derived_heuristic_confidence=c.derived_heuristic_confidence,
            severity=c.severity.value if c.severity else None,
            providers_evaluated=c.providers_evaluated,
            failed_providers=c.failed_providers,
            agreeing_providers=c.agreeing_providers,
            conflicting_providers=c.conflicting_providers,
            rationale=c.rationale,
            is_derived=c.is_derived,
        )


class EnrichedObservableSchema(BaseModel):
    """Enriched observable result bundle."""

    ioc_type: str
    raw_value: str
    canonical_value: str
    is_routable_external: bool
    consensus: ConsensusSchema
    provider_results: list[ProviderResultSchema] = Field(default_factory=list)

    @classmethod
    def from_domain(cls, eo: EnrichedObservable) -> EnrichedObservableSchema:
        return cls(
            ioc_type=eo.observable.ioc_type.value,
            raw_value=eo.observable.raw_value,
            canonical_value=eo.observable.canonical_value,
            is_routable_external=eo.observable.is_routable_external,
            consensus=ConsensusSchema.from_domain(eo.consensus),
            provider_results=[ProviderResultSchema.from_domain(r) for r in eo.provider_results],
        )


class EnrichmentBatchResponse(BaseModel):
    """Response containing batch enrichment results."""

    total: int
    results: list[EnrichedObservableSchema]


class EventEnrichmentResponse(BaseModel):
    """Response for event enrichment."""

    event_id: uuid.UUID
    total_observables: int
    results: list[EnrichedObservableSchema]


class IncidentEnrichmentResponse(BaseModel):
    """Response for incident enrichment."""

    incident_id: uuid.UUID
    total_observables: int
    results: list[EnrichedObservableSchema]


class ThreatIntelResultItem(BaseModel):
    """Database historical record representation."""

    id: uuid.UUID
    normalized_event_id: uuid.UUID | None = None
    incident_id: uuid.UUID | None = None
    ioc_type: str
    ioc_value: str
    source: str
    matched: bool
    verdict: str
    severity: str | None = None
    confidence: float | None = None
    provider_confidence: float | None = None
    derived_heuristic_confidence: float | None = None
    threat_type: str | None = None
    context: dict[str, Any] | None = None
    raw_response_text: str | None = None
    source_reference: str | None = None
    queried_at: datetime
    cache_expires_at: datetime
    created_at: datetime


class ThreatIntelResultListResponse(BaseModel):
    """Paginated list of historical CTI records."""

    total: int
    limit: int
    offset: int
    results: list[ThreatIntelResultItem]


class ProviderStatusListResponse(BaseModel):
    """Operational status and health of CTI providers."""

    status: str
    cache: dict[str, Any]
    providers: list[dict[str, Any]]


class CacheInvalidateRequest(BaseModel):
    """Cache invalidation request."""

    provider: str | None = Field(default=None, description="Target provider (e.g. 'local_feed', 'abuseipdb')")
    ioc_type: str | None = Field(default=None, description="Target IOC type ('ip', 'domain', 'url', 'file_hash', 'email')")
    ioc_value: str | None = Field(default=None, description="Target canonical observable value")
    key_pattern: str | None = Field(default=None, description="Optional raw key pattern (e.g. 'ti:cache:local_feed:*')")


class CacheInvalidateResponse(BaseModel):
    """Cache invalidation confirmation."""

    deleted_entries: int
    target: str
    invalidated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
