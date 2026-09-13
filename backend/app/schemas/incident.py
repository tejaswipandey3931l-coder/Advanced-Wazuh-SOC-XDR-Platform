"""
Pydantic schemas for Incidents and Correlation Rules API.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field

from backend.app.models.correlation_rule import RuleType
from backend.app.models.incident import IncidentSeverity, IncidentStatus


class IncidentEventItem(BaseModel):
    """Schema representing an event linked to an incident."""

    model_config = ConfigDict(from_attributes=True)

    id: UUID
    incident_id: UUID
    normalized_event_id: UUID
    correlation_rule_id: UUID | None = None
    match_role: str | None = None
    confidence: float
    added_at: datetime


class IncidentResponse(BaseModel):
    """Summary schema for an incident."""

    model_config = ConfigDict(from_attributes=True)

    id: UUID
    title: str
    description: str | None = None
    status: IncidentStatus
    severity: IncidentSeverity
    confidence: float
    first_seen: datetime
    last_seen: datetime
    alert_count: int
    dedup_key: str | None = None
    correlation_rule_id: UUID | None = None
    entity_context: dict[str, Any] | None = None
    mitre_techniques: list[str] | None = None
    mitre_tactics: list[str] | None = None
    created_at: datetime
    updated_at: datetime


class IncidentDetailResponse(IncidentResponse):
    """Detailed schema for an incident including linked events."""

    events: list[IncidentEventItem] = Field(default_factory=list)


class IncidentListResponse(BaseModel):
    """Paginated response of incidents."""

    items: list[IncidentResponse]
    total: int
    limit: int
    offset: int


class IncidentEventsListResponse(BaseModel):
    """List of events linked to an incident."""

    items: list[IncidentEventItem]
    total: int


class EvaluateEventRequest(BaseModel):
    """Request to evaluate a specific normalized event through the correlation engine."""

    event_id: UUID


class EvaluateEventResponse(BaseModel):
    """Response containing any incidents created or updated by event evaluation."""

    evaluated: bool
    event_id: UUID
    matches_count: int
    incidents: list[IncidentResponse] = Field(default_factory=list)


class CorrelationRuleResponse(BaseModel):
    """Schema representing a correlation rule."""

    model_config = ConfigDict(from_attributes=True)

    id: UUID
    name: str
    description: str | None = None
    rule_type: RuleType
    severity: str
    base_confidence: float
    time_window_seconds: int
    min_event_count: int
    entity_field: str | None = None
    conditions: dict[str, Any] | None = None
    is_active: bool
    priority: int
    version: int
    mitre_technique_id: str | None = None
    mitre_tactic_id: str | None = None
    created_at: datetime
    updated_at: datetime


class CorrelationRuleCreateRequest(BaseModel):
    """Request schema to create a new correlation rule."""

    name: str = Field(..., min_length=1, max_length=255)
    description: str | None = None
    rule_type: RuleType
    severity: str = "medium"
    base_confidence: float = Field(default=0.7, ge=0.0, le=1.0)
    time_window_seconds: int = Field(default=300, gt=0, le=86400)
    min_event_count: int = Field(default=2, ge=1)
    entity_field: str | None = None
    conditions: dict[str, Any] | None = None
    is_active: bool = True
    priority: int = 100
    mitre_technique_id: str | None = None
    mitre_tactic_id: str | None = None


class CorrelationRulesListResponse(BaseModel):
    """List of correlation rules."""

    items: list[CorrelationRuleResponse]
    total: int
