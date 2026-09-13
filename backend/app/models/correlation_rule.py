"""
CorrelationRule model.

Stores the configuration for rules used by the correlation engine to group
NormalizedEvents into Incidents.

Rule types:
  - ``entity_group``:  events sharing the same entity field value within a
                       time window are grouped into one incident.
  - ``temporal``:      events occurring within a time window exceeding a
                       frequency threshold are grouped.
  - ``sequence``:      events must appear in a defined order within a window.
                       (Sequence matching is deferred to Phase 3 implementation.)

Rules are evaluated by the correlation engine in Phase 3.  This model
provides the configurable, DB-persisted rule definitions.
"""

from __future__ import annotations

import enum

from sqlalchemy import Boolean, Enum, Float, Index, Integer, String, Text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from .base import Base, TimestampMixin, UUIDPrimaryKeyMixin


class RuleType(str, enum.Enum):
    ENTITY_GROUP = "entity_group"
    TEMPORAL = "temporal"
    SEQUENCE = "sequence"


class CorrelationRule(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """A rule that instructs the correlation engine how to group events."""

    __tablename__ = "correlation_rules"

    # ── Identity ──────────────────────────────────────────────────────────────
    name: Mapped[str] = mapped_column(String(255), unique=True, nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    is_active: Mapped[bool] = mapped_column(
        Boolean, default=True, nullable=False, index=True
    )
    version: Mapped[int] = mapped_column(Integer, default=1, nullable=False)
    severity: Mapped[str] = mapped_column(String(32), default="medium", nullable=False)
    base_confidence: Mapped[float] = mapped_column(Float, default=0.7, nullable=False)
    mitre_technique_id: Mapped[str | None] = mapped_column(String(32), nullable=True)
    mitre_tactic_id: Mapped[str | None] = mapped_column(String(32), nullable=True)

    # ── Rule configuration ────────────────────────────────────────────────────
    rule_type: Mapped[RuleType] = mapped_column(
        Enum(
            RuleType,
            name="correlation_rule_type",
            values_callable=lambda x: [e.value for e in x],
        ),
        nullable=False,
        index=True,
    )

    # For entity_group / sequence rules: the NormalizedEvent field to match on.
    # e.g. "src_ip", "user", "hostname", "agent_id"
    entity_field: Mapped[str | None] = mapped_column(String(128), nullable=True)

    # Correlation window in seconds.
    time_window_seconds: Mapped[int] = mapped_column(
        Integer, default=300, nullable=False
    )

    # Minimum number of matching events to form / extend an incident.
    min_event_count: Mapped[int] = mapped_column(Integer, default=2, nullable=False)

    # Additional filter conditions (JSON predicate against NormalizedEvent fields).
    # e.g. {"severity": {"gte": 5}, "source_type": "wazuh_agent"}
    conditions: Mapped[dict | None] = mapped_column(JSONB, nullable=True)

    # Priority: lower number = evaluated first.
    priority: Mapped[int] = mapped_column(Integer, default=100, nullable=False)

    # ── Composite indexes ─────────────────────────────────────────────────────
    __table_args__ = (
        Index("ix_corr_rules_active_priority", "is_active", "priority"),
    )

    def __repr__(self) -> str:
        return (
            f"<CorrelationRule id={self.id!s:.8} "
            f"name={self.name!r} "
            f"type={self.rule_type.value!r} "
            f"active={self.is_active}>"
        )
