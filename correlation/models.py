"""
Pydantic schemas and definitions for the Correlation Engine.
"""

from __future__ import annotations

import enum
import re
from datetime import datetime, timezone
from typing import Any
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from backend.app.models.correlation_rule import RuleType
from backend.app.models.incident import IncidentSeverity


def evaluate_condition_value(op: str, actual_val: Any, expected_val: Any) -> bool:
    """Evaluates a single predicate operator against actual event value."""
    if op == "eq":
        return actual_val == expected_val
    elif op == "neq":
        return actual_val != expected_val
    elif op == "gt":
        if actual_val is None:
            return False
        return actual_val > expected_val
    elif op == "gte":
        if actual_val is None:
            return False
        return actual_val >= expected_val
    elif op == "lt":
        if actual_val is None:
            return False
        return actual_val < expected_val
    elif op == "lte":
        if actual_val is None:
            return False
        return actual_val <= expected_val
    elif op == "in":
        if isinstance(expected_val, (list, tuple, set)):
            return actual_val in expected_val
        return False
    elif op == "not_in":
        if isinstance(expected_val, (list, tuple, set)):
            return actual_val not in expected_val
        return True
    elif op == "contains":
        if actual_val is None:
            return False
        return str(expected_val) in str(actual_val)
    elif op == "regex":
        if actual_val is None:
            return False
        return bool(re.search(str(expected_val), str(actual_val)))
    elif op == "exists":
        exists = actual_val is not None
        return exists if expected_val else not exists
    return False


def matches_conditions(event_dict: dict[str, Any], conditions: dict[str, Any] | None) -> bool:
    """
    Evaluates whether an event dictionary matches a nested or simple condition dictionary.
    Supports:
      {"severity": {"gte": 5}}
      {"auth_result": "failed"}
      {"rule_id": {"in": ["5710", "5715"]}}
    """
    if not conditions:
        return True

    for field_name, expected in conditions.items():
        actual_val = event_dict.get(field_name)

        if isinstance(expected, dict):
            # Compound operators e.g. {"gte": 5, "lte": 10}
            for op, val in expected.items():
                if not evaluate_condition_value(op, actual_val, val):
                    return False
        else:
            # Direct equality check
            if actual_val != expected:
                return False

    return True


class SequenceStepDefinition(BaseModel):
    """Definition of a single step within an ordered sequence rule."""

    model_config = ConfigDict(frozen=True)

    step_id: str = Field(..., min_length=1, max_length=64)
    name: str = Field(..., min_length=1, max_length=128)
    conditions: dict[str, Any] = Field(
        default_factory=dict,
        description="Event attribute filter conditions that must match for this step.",
    )
    min_count: int = Field(
        default=1,
        ge=1,
        description="Minimum number of events required for this sequence step.",
    )
    description: str | None = None

    @field_validator("conditions")
    @classmethod
    def validate_conditions(cls, v: dict[str, Any]) -> dict[str, Any]:
        valid_ops = {"eq", "neq", "gt", "gte", "lt", "lte", "in", "not_in", "contains", "regex", "exists"}
        for k, expr in v.items():
            if isinstance(expr, dict):
                for op in expr.keys():
                    if op not in valid_ops:
                        raise ValueError(f"Unknown operator '{op}' in conditions for field '{k}'")
        return v


class CorrelationRuleDefinition(BaseModel):
    """
    Complete configuration for a correlation rule loaded from database or code.
    Validates structural consistency and rejects ambiguous rule definitions.
    """

    model_config = ConfigDict(from_attributes=True)

    id: UUID = Field(default_factory=uuid4)
    name: str = Field(..., min_length=1, max_length=255)
    description: str | None = None
    rule_type: RuleType
    severity: IncidentSeverity = IncidentSeverity.MEDIUM
    base_confidence: float = Field(default=0.7, ge=0.0, le=1.0)
    time_window_seconds: int = Field(gt=0, le=86400, description="Correlation window in seconds")
    min_event_count: int = Field(default=2, ge=1)
    entity_field: str | None = Field(default=None, max_length=128)
    distinct_entity_field: str | None = Field(default=None, max_length=128)
    min_distinct_count: int | None = Field(default=None, ge=2)
    conditions: dict[str, Any] | None = None
    sequence_steps: list[SequenceStepDefinition] = Field(default_factory=list)
    mitre_technique_id: str | None = Field(default=None, max_length=32)
    mitre_tactic_id: str | None = Field(default=None, max_length=32)
    is_active: bool = True
    priority: int = 100
    version: int = Field(default=1, ge=1)

    @field_validator("conditions")
    @classmethod
    def validate_conditions(cls, v: dict[str, Any] | None) -> dict[str, Any] | None:
        if v is None:
            return v
        valid_ops = {"eq", "neq", "gt", "gte", "lt", "lte", "in", "not_in", "contains", "regex", "exists"}
        for k, expr in v.items():
            if isinstance(expr, dict):
                for op in expr.keys():
                    if op not in valid_ops:
                        raise ValueError(f"Unknown operator '{op}' in rule condition for field '{k}'")
        return v

    @model_validator(mode="after")
    def validate_rule_semantics(self) -> CorrelationRuleDefinition:
        if self.rule_type == RuleType.SEQUENCE:
            if len(self.sequence_steps) < 2:
                raise ValueError("Sequence rules must define at least 2 ordered sequence_steps.")
            if not self.entity_field:
                raise ValueError("Sequence rules require an entity_field to bind steps to a single entity.")
        elif self.rule_type == RuleType.ENTITY_GROUP:
            if not self.entity_field:
                raise ValueError("Entity group rules require an entity_field (e.g. 'src_ip', 'user').")
            if self.sequence_steps:
                raise ValueError("Entity group rules must not define sequence_steps.")
        elif self.rule_type == RuleType.TEMPORAL:
            if self.sequence_steps:
                raise ValueError("Temporal rules must not define sequence_steps.")

        if self.distinct_entity_field and not self.min_distinct_count:
            raise ValueError("Rules defining distinct_entity_field must specify min_distinct_count >= 2.")

        return self


class WindowItem(BaseModel):
    """An event representation stored in sliding correlation windows."""

    model_config = ConfigDict(frozen=True)

    event_id: UUID
    event_timestamp: datetime
    ingestion_timestamp: datetime
    entity_value: str
    data: dict[str, Any]

    @field_validator("event_timestamp", "ingestion_timestamp")
    @classmethod
    def ensure_utc(cls, v: datetime) -> datetime:
        if v.tzinfo is None:
            return v.replace(tzinfo=timezone.utc)
        return v.astimezone(timezone.utc)


class CorrelationMatch(BaseModel):
    """Structured match output produced by the pure evaluation layer."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    match_id: UUID = Field(default_factory=uuid4)
    rule: CorrelationRuleDefinition
    entity_field: str
    entity_value: str
    matched_event_ids: list[UUID]
    matched_events: list[dict[str, Any]]
    first_seen: datetime
    last_seen: datetime
    confidence: float = Field(ge=0.0, le=1.0)
    confidence_rationale: str
    event_roles: dict[UUID, str]
    mitre_techniques: list[str] = Field(default_factory=list)
    mitre_tactics: list[str] = Field(default_factory=list)
