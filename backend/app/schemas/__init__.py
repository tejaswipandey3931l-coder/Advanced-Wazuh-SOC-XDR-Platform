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
]
