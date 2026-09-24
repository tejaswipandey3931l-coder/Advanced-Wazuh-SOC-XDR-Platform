"""
Domain and API models for Phase 5 Risk Engine (risk-v1).
"""

from __future__ import annotations

import enum
import uuid
from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class PriorityBand(str, enum.Enum):
    """Deterministic priority bands mapping from operational risk score."""

    INFORMATIONAL = "INFORMATIONAL"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class FactorInputs(BaseModel):
    """Evidentiary input factors consumed by the risk calculation engine."""

    model_config = ConfigDict(extra="ignore")

    wazuh_levels: list[int] = Field(default_factory=list, description="Wazuh alert rule levels (1-16)")
    incident_severity: str = Field(default="medium", description="Phase 3 incident anchor severity")
    rule_confidence: float | None = Field(default=None, ge=0.0, le=1.0, description="Correlation rule base confidence")
    rule_type: str | None = Field(default=None, description="Correlation rule type")
    rule_priority: int | None = Field(default=None, ge=0, description="Correlation rule priority (0-100)")
    is_correlated: bool = Field(default=True, description="True if incident matched a correlation rule, False for fallback")
    alert_count: int = Field(default=1, ge=1, description="Total number of alerts associated with incident")
    distinct_entities: int = Field(default=1, ge=1, description="Number of distinct entities (hosts/users/IPs)")
    mitre_tactics: list[str] = Field(default_factory=list, description="List of unique MITRE tactics tagged in alerts")
    observables_cti: list[dict[str, Any]] = Field(
        default_factory=list,
        description="CTI evaluation records for incident observables with verdict, confidences, etc.",
    )
    last_seen: datetime = Field(description="Timestamp of the most recent alert associated with incident")
    evidence_as_of: datetime = Field(description="Newest evidence timestamp represented by this snapshot")
    evidence_version: int = Field(default=1, ge=1, description="Monotonic database evidence snapshot version")
    evaluation_as_of: datetime = Field(description="Logical evaluation timestamp used for temporal decay")


class ComponentScores(BaseModel):
    """Individual factor scores normalized to [0.0, 100.0] (volume capped at 90.0)."""

    severity: float = Field(ge=0.0, le=100.0)
    correlation: float = Field(ge=0.0, le=100.0)
    cti: float = Field(ge=0.0, le=100.0)
    volume: float = Field(ge=0.0, le=90.0)
    mitre_coverage: float = Field(ge=0.0, le=100.0)


class ComponentContributions(BaseModel):
    """Weighted contributions to the base score (weights * factor scores)."""

    severity: float
    correlation: float
    cti: float
    volume: float
    mitre_coverage: float


class RiskExplanation(BaseModel):
    """Structured, human-auditable and machine-readable risk score explanation."""

    incident_id: str | None = None
    evidence_as_of: datetime
    evidence_version: int
    evaluation_as_of: datetime
    calculated_at: datetime
    overall_score: float = Field(ge=0.0, le=100.0)
    priority_band: PriorityBand
    base_score: float = Field(ge=0.0, le=99.0)
    temporal_decay: float = Field(ge=0.25, le=1.0)
    contributions: ComponentContributions
    mitigations: dict[str, float]
    weights_used: dict[str, float]
    conservation_verified: bool
    summary: str


class RiskResult(BaseModel):
    """Complete output of a risk-v1 evaluation."""

    overall_score: float = Field(ge=0.0, le=100.0)
    priority_band: PriorityBand
    base_score: float = Field(ge=0.0, le=99.0)
    temporal_decay: float = Field(ge=0.25, le=1.0)
    sub_scores: ComponentScores
    effective_weights: dict[str, float]
    factors: dict[str, Any]
    explanation: RiskExplanation
    evidence_version: int
    evidence_as_of: datetime
    evaluation_as_of: datetime
    calculated_at: datetime
    clean_mitigation: float = 0.0
    risk_score_id: uuid.UUID | None = None


class RiskRecalculateRequest(BaseModel):
    """Request payload for manual recalculation."""

    evaluation_as_of: datetime | None = Field(
        default=None,
        description="Optional custom logical evaluation timestamp. Defaults to current UTC time.",
    )


class RiskSimulateRequest(BaseModel):
    """Stateless simulation payload."""

    factors: FactorInputs
