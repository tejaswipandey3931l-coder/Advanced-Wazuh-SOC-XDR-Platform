"""
Pydantic data schemas for API requests and responses.
"""

from __future__ import annotations

from .incident import (
    CorrelationRuleCreateRequest,
    CorrelationRuleResponse,
    CorrelationRulesListResponse,
    EvaluateEventRequest,
    EvaluateEventResponse,
    IncidentDetailResponse,
    IncidentEventItem,
    IncidentEventsListResponse,
    IncidentListResponse,
    IncidentResponse,
)
from .wazuh import (
    AlertListResponse,
    RawAlertItem,
    WazuhApiInfo,
    WazuhManagerInfo,
    WazuhManagerStatus,
)

from .threat_intel import (
    CacheInvalidateRequest,
    CacheInvalidateResponse,
    ConsensusSchema,
    EnrichedObservableSchema,
    EnrichmentBatchResponse,
    EnrichmentRequest,
    EventEnrichmentResponse,
    IncidentEnrichmentResponse,
    ObservableInput,
    ProviderResultSchema,
    ProviderStatusListResponse,
    ThreatIntelResultItem,
    ThreatIntelResultListResponse,
)
from .risk import (
    RiskHistoryResponse,
    RiskRecalculateRequest,
    RiskScoreResponse,
    RiskSimulateRequest,
    RiskSimulateResponse,
)

__all__ = [
    "AlertListResponse",
    "RawAlertItem",
    "WazuhApiInfo",
    "WazuhManagerInfo",
    "WazuhManagerStatus",
    "IncidentResponse",
    "IncidentDetailResponse",
    "IncidentListResponse",
    "IncidentEventItem",
    "IncidentEventsListResponse",
    "EvaluateEventRequest",
    "EvaluateEventResponse",
    "CorrelationRuleResponse",
    "CorrelationRuleCreateRequest",
    "CorrelationRulesListResponse",
    "ObservableInput",
    "EnrichmentRequest",
    "ProviderResultSchema",
    "ConsensusSchema",
    "EnrichedObservableSchema",
    "EnrichmentBatchResponse",
    "EventEnrichmentResponse",
    "IncidentEnrichmentResponse",
    "ThreatIntelResultItem",
    "ThreatIntelResultListResponse",
    "ProviderStatusListResponse",
    "CacheInvalidateRequest",
    "CacheInvalidateResponse",
    "RiskScoreResponse",
    "RiskHistoryResponse",
    "RiskRecalculateRequest",
    "RiskSimulateRequest",
    "RiskSimulateResponse",
]
