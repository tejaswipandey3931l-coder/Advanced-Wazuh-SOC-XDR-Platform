"""
Incident model.

An Incident is created when the correlation engine groups two or more
related NormalizedEvents into a coherent security incident.  A single
alert that is independently significant may also be promoted to an
Incident by the correlation engine.

The ``status`` lifecycle is:  open → investigating → closed | false_positive
"""

from __future__ import annotations

import enum
import uuid
from datetime import datetime

from typing import TYPE_CHECKING

from sqlalchemy import (
    DateTime,
    Enum,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    text,
)
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .base import Base, TimestampMixin, UUIDPrimaryKeyMixin

if TYPE_CHECKING:
    from .attack_chain import AttackChain
    from .correlation_rule import CorrelationRule
    from .incident_event import IncidentEvent
    from .normalized_event import NormalizedEvent


class IncidentStatus(str, enum.Enum):
    OPEN = "open"
    INVESTIGATING = "investigating"
    CLOSED = "closed"
    FALSE_POSITIVE = "false_positive"


class IncidentSeverity(str, enum.Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFORMATIONAL = "informational"


class Incident(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """A correlated group of security events forming a single incident."""

    __tablename__ = "incidents"

    # ── Identification ────────────────────────────────────────────────────────
    title: Mapped[str] = mapped_column(String(512), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)

    # ── Status ────────────────────────────────────────────────────────────────
    status: Mapped[IncidentStatus] = mapped_column(
        Enum(
            IncidentStatus,
            name="incident_status",
            values_callable=lambda x: [e.value for e in x],
        ),
        default=IncidentStatus.OPEN,
        nullable=False,
        index=True,
    )
    severity: Mapped[IncidentSeverity] = mapped_column(
        Enum(
            IncidentSeverity,
            name="incident_severity",
            values_callable=lambda x: [e.value for e in x],
        ),
        default=IncidentSeverity.MEDIUM,
        nullable=False,
        index=True,
    )

    # ── Scoring (populated by risk engine and ML prioritiser) ─────────────────
    risk_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    ml_priority_score: Mapped[float | None] = mapped_column(Float, nullable=True)

    # ── Timeline ──────────────────────────────────────────────────────────────
    first_seen: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, index=True
    )
    last_seen: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, index=True
    )
    alert_count: Mapped[int] = mapped_column(Integer, default=1, nullable=False)

    # ── Correlation Context (Phase 3) ─────────────────────────────────────────
    correlation_rule_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("correlation_rules.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    confidence: Mapped[float] = mapped_column(Float, default=1.0, nullable=False)
    dedup_key: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)

    # ── MITRE context ─────────────────────────────────────────────────────────
    # Aggregated from member events by the correlation engine.
    mitre_techniques: Mapped[list | None] = mapped_column(JSONB, nullable=True)
    mitre_tactics: Mapped[list | None] = mapped_column(JSONB, nullable=True)

    # ── Threat intel flags ────────────────────────────────────────────────────
    ioc_matched: Mapped[bool] = mapped_column(
        default=False, nullable=False
    )

    # ── Correlated entity context (populated by correlation engine) ───────────
    # e.g. {"src_ip": "10.0.0.5", "user": "jsmith", "hostname": "web01"}
    entity_context: Mapped[dict | None] = mapped_column(JSONB, nullable=True)

    # ── Relationships ─────────────────────────────────────────────────────────
    attack_chain: Mapped["AttackChain | None"] = relationship(
        "AttackChain", back_populates="incident", uselist=False
    )
    correlation_rule: Mapped["CorrelationRule | None"] = relationship(
        "CorrelationRule"
    )
    incident_events: Mapped[list["IncidentEvent"]] = relationship(
        "IncidentEvent", back_populates="incident", cascade="all, delete-orphan"
    )
    events: Mapped[list["NormalizedEvent"]] = relationship(
        "NormalizedEvent", secondary="incident_events", viewonly=True
    )
    threat_intel_results: Mapped[list["ThreatIntelResult"]] = relationship(
        "ThreatIntelResult", back_populates="incident", cascade="all, delete-orphan"
    )

    # ── Composite indexes ──────────────────────────────────────────────────────
    __table_args__ = (
        Index("ix_incidents_status_severity", "status", "severity"),
        Index("ix_incidents_first_seen", "first_seen"),
        Index(
            "uq_active_incident_dedup_key",
            "dedup_key",
            unique=True,
            postgresql_where=text("status IN ('open', 'investigating')"),
        ),
    )

    def __repr__(self) -> str:
        return (
            f"<Incident id={self.id!s:.8} "
            f"status={self.status.value!r} "
            f"severity={self.severity.value!r} "
            f"risk={self.risk_score}>"
        )
