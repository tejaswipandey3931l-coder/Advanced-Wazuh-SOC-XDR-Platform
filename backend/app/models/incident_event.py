"""
IncidentEvent junction model.

Associates NormalizedEvents to an Incident with correlation role,
rule reference, confidence score, and timestamp.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import TYPE_CHECKING

from sqlalchemy import (
    DateTime,
    Float,
    ForeignKey,
    Index,
    String,
    UniqueConstraint,
)
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .base import Base, UUIDPrimaryKeyMixin

if TYPE_CHECKING:
    from .correlation_rule import CorrelationRule
    from .incident import Incident
    from .normalized_event import NormalizedEvent


class IncidentEvent(UUIDPrimaryKeyMixin, Base):
    """Junction table linking a NormalizedEvent to an Incident."""

    __tablename__ = "incident_events"

    # ── Foreign Keys ──────────────────────────────────────────────────────────
    incident_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("incidents.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    normalized_event_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("normalized_events.id", ondelete="RESTRICT"),
        nullable=False,
        index=True,
    )
    correlation_rule_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("correlation_rules.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )

    # ── Metadata ──────────────────────────────────────────────────────────────
    # Role of this event in the correlation (e.g. 'threshold_member', 'sequence_step_1')
    match_role: Mapped[str | None] = mapped_column(String(64), nullable=True)
    confidence: Mapped[float] = mapped_column(Float, default=1.0, nullable=False)
    added_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )

    # ── Relationships ─────────────────────────────────────────────────────────
    incident: Mapped["Incident"] = relationship(
        "Incident", back_populates="incident_events"
    )
    normalized_event: Mapped["NormalizedEvent"] = relationship(
        "NormalizedEvent", back_populates="incident_events"
    )
    correlation_rule: Mapped["CorrelationRule | None"] = relationship(
        "CorrelationRule"
    )

    # ── Table Constraints & Indexes ───────────────────────────────────────────
    __table_args__ = (
        UniqueConstraint(
            "incident_id",
            "normalized_event_id",
            name="uq_incident_events_incident_event",
        ),
        Index("ix_incident_events_incident_id", "incident_id"),
        Index("ix_incident_events_event_id", "normalized_event_id"),
    )

    def __repr__(self) -> str:
        return (
            f"<IncidentEvent id={self.id!s:.8} "
            f"incident_id={self.incident_id!s:.8} "
            f"event_id={self.normalized_event_id!s:.8} "
            f"role={self.match_role!r}>"
        )
