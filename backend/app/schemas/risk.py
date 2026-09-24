"""
Pydantic schemas for Phase 5 Dynamic Risk Scoring & Alert Prioritization API.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field

from risk_engine.models import FactorInputs, PriorityBand, RiskExplanation, RiskResult


class RiskScoreResponse(BaseModel):
    """Schema representing a calculated risk score evaluation for an incident."""

    model_config = ConfigDict(from_attributes=True)

    id: UUID | None = None
    incident_id: UUID
    scoring_version: str = "risk-v1"
    overall_score: float = Field(ge=0.0, le=100.0)
    priority_band: str
    base_score: float = Field(ge=0.0, le=99.0)
    temporal_decay: float = Field(ge=0.25, le=1.0)
    severity_score: float
    correlation_score: float
    cti_score: float
    volume_score: float
    mitre_score: float
    effective_weights: dict[str, float]
    factors: dict[str, Any]
    explanation: dict[str, Any]
    trigger_reason: str = "manual"
    evidence_as_of: datetime
    evidence_version: int
    evaluation_as_of: datetime
    calculated_at: datetime

    @classmethod
    def from_domain(cls, result: RiskResult, incident_id: UUID, score_id: UUID | None = None, trigger_reason: str = "manual") -> RiskScoreResponse:
        return cls(
            id=score_id,
            incident_id=incident_id,
            scoring_version="risk-v1",
            overall_score=result.overall_score,
            priority_band=result.priority_band.value,
            base_score=result.base_score,
            temporal_decay=result.temporal_decay,
            severity_score=result.sub_scores.severity,
            correlation_score=result.sub_scores.correlation,
            cti_score=result.sub_scores.cti,
            volume_score=result.sub_scores.volume,
            mitre_score=result.sub_scores.mitre_coverage,
            effective_weights=result.effective_weights,
            factors=result.factors,
            explanation=result.explanation.model_dump(mode="json"),
            trigger_reason=trigger_reason,
            evidence_as_of=result.evidence_as_of,
            evidence_version=result.evidence_version,
            evaluation_as_of=result.evaluation_as_of,
            calculated_at=result.calculated_at,
        )


class RiskHistoryResponse(BaseModel):
    """Paginated list of append-only risk score history entries."""

    incident_id: UUID
    items: list[RiskScoreResponse]
    total: int


class RiskRecalculateRequest(BaseModel):
    """Request payload for manual risk recalculation."""

    evaluation_as_of: datetime | None = Field(
        default=None,
        description="Optional custom logical evaluation timestamp. Defaults to current UTC time.",
    )


class RiskSimulateRequest(BaseModel):
    """Stateless risk calculation simulation payload."""

    factors: FactorInputs


class RiskSimulateResponse(BaseModel):
    """Result of a stateless risk simulation."""

    overall_score: float = Field(ge=0.0, le=100.0)
    priority_band: str
    base_score: float = Field(ge=0.0, le=99.0)
    temporal_decay: float = Field(ge=0.25, le=1.0)
    sub_scores: dict[str, float]
    effective_weights: dict[str, float]
    factors: dict[str, Any]
    explanation: dict[str, Any]
    clean_mitigation: float = 0.0
    evidence_version: int
    evidence_as_of: datetime
    evaluation_as_of: datetime
    calculated_at: datetime
