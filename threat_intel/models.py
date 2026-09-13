"""
Pydantic v2 domain schemas and enums for Phase 4 Threat Intelligence Enrichment.
"""

from __future__ import annotations

from datetime import datetime, timezone
import enum
from typing import Any
from pydantic import BaseModel, ConfigDict, Field

from backend.app.models.threat_intel_result import IOCType, CTISource


class ThreatVerdict(str, enum.Enum):
    MALICIOUS = "malicious"
    SUSPICIOUS = "suspicious"
    BENIGN = "benign"
    UNKNOWN = "unknown"
    CONFLICT = "conflict"


class ThreatSeverity(str, enum.Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"
    NONE = "none"


class ProviderStatus(str, enum.Enum):
    SUCCESS = "success"
    NOT_FOUND = "not_found"
    RATE_LIMITED = "rate_limited"
    TIMEOUT = "timeout"
    AUTH_ERROR = "auth_error"
    NETWORK_ERROR = "network_error"


class IPClassification(str, enum.Enum):
    PUBLIC = "public"
    PRIVATE = "private"
    LOOPBACK = "loopback"
    LINK_LOCAL = "link_local"
    MULTICAST = "multicast"
    RESERVED = "reserved"


class NormalizedObservable(BaseModel):
    """Canonicalized security observable ready for enrichment."""

    model_config = ConfigDict(frozen=True)

    ioc_type: IOCType
    raw_value: str
    canonical_value: str
    ip_classification: IPClassification | None = None
    is_routable_external: bool = True
    source_field: str | None = None


class ProviderResult(BaseModel):
    """Structured result returned from a single CTI provider lookup."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    provider: str
    observable: NormalizedObservable
    status: ProviderStatus
    verdict: ThreatVerdict
    severity: ThreatSeverity | None = None

    # Native provider-reported confidence (e.g. AbuseIPDB abuse score / 100)
    provider_confidence: float | None = Field(default=None, ge=0.0, le=1.0)
    # Heuristic confidence derived by platform rules (explicitly uncalibrated)
    derived_heuristic_confidence: float | None = Field(default=None, ge=0.0, le=1.0)

    threat_types: list[str] = Field(default_factory=list)
    raw_payload: dict[str, Any] = Field(default_factory=dict)
    raw_response_text: str | None = None
    source_reference: str | None = None
    queried_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    cached: bool = False
    error_message: str | None = None


class EnrichmentConsensus(BaseModel):
    """
    Derived multi-provider consensus for an observable.
    Preserves transparent, explainable conflict detection without inventing opaque scores.
    """

    model_config = ConfigDict(arbitrary_types_allowed=True)

    verdict: ThreatVerdict
    provider_confidence: float | None = None
    derived_heuristic_confidence: float | None = None
    severity: ThreatSeverity | None = None
    providers_evaluated: list[str] = Field(default_factory=list)
    failed_providers: list[str] = Field(default_factory=list)
    agreeing_providers: list[str] = Field(default_factory=list)
    conflicting_providers: list[str] = Field(default_factory=list)
    rationale: str
    is_derived: bool = True


class EnrichedObservable(BaseModel):
    """Aggregated enrichment bundle for an observable containing all provider evidence and derived consensus."""

    observable: NormalizedObservable
    consensus: EnrichmentConsensus
    provider_results: list[ProviderResult] = Field(default_factory=list)


class ProviderHealth(BaseModel):
    """Health check status and latency for a CTI provider."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    provider: str
    status: str  # "healthy", "degraded", "unhealthy", "disabled"
    enabled: bool
    latency_ms: float | None = None
    rate_limit_remaining: int | None = None
    error_message: str | None = None
    checked_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
