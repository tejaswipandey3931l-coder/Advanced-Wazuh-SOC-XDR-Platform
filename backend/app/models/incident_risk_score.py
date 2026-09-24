"""
IncidentRiskScore model.

Represents an append-only historical audit record of an operational priority
risk calculation for an incident according to risk-v1 specification.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any

from sqlalchemy import (
    BigInteger,
    DateTime,
    Float,
    ForeignKey,
    Index,
    String,
)
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .base import Base, UUIDPrimaryKeyMixin

if TYPE_CHECKING:
    from .incident import Incident


class IncidentRiskScore(UUIDPrimaryKeyMixin, Base):
    """Append-only audit trail of calculated operational incident risk scores."""

    __tablename__ = "incident_risk_scores"

    # ── Parent Incident ───────────────────────────────────────────────────────
    # ON DELETE RESTRICT prevents silent destruction of historical risk audit trail
    incident_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("incidents.id", ondelete="RESTRICT"),
        nullable=False,
        index=True,
    )

    # ── Scoring Metadata ──────────────────────────────────────────────────────
    scoring_version: Mapped[str] = mapped_column(
        String(32), default="risk-v1", nullable=False
    )
    overall_score: Mapped[float] = mapped_column(Float, nullable=False)
    priority_band: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    base_score: Mapped[float] = mapped_column(Float, nullable=False)
    temporal_decay: Mapped[float] = mapped_column(Float, nullable=False)

    # ── Component Factor Sub-scores ───────────────────────────────────────────
    severity_score: Mapped[float] = mapped_column(Float, nullable=False)
    correlation_score: Mapped[float] = mapped_column(Float, nullable=False)
    cti_score: Mapped[float] = mapped_column(Float, nullable=False)
    volume_score: Mapped[float] = mapped_column(Float, nullable=False)
    mitre_score: Mapped[float] = mapped_column(Float, nullable=False)

    # ── Detailed Structured Dictionaries ──────────────────────────────────────
    effective_weights: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
    factors: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
    explanation: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
    trigger_reason: Mapped[str] = mapped_column(String(64), nullable=False)

    # ── Four Explicit Temporal Concepts ───────────────────────────────────────
    # 1. evidence_version: monotonic identifier of the exact database evidence snapshot
    evidence_version: Mapped[int] = mapped_column(BigInteger, nullable=False)
    # 2. evidence_as_of: chronological horizon of newest evidence ingested
    evidence_as_of: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    # 3. evaluation_as_of: logical evaluation timestamp for temporal decay
    evaluation_as_of: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    # 4. calculated_at: wall-clock calculation completion timestamp (audit metadata only)
    calculated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )

    # ── Relationships ─────────────────────────────────────────────────────────
    incident: Mapped["Incident"] = relationship(
        "Incident",
        back_populates="risk_scores",
        foreign_keys=[incident_id],
    )

    # ── Indexes ───────────────────────────────────────────────────────────────
    __table_args__ = (
        Index(
            "ix_incident_risk_scores_incident_calc",
            "incident_id",
            calculated_at.desc(),
        ),
        Index(
            "ix_incident_risk_scores_incident_ver",
            "incident_id",
            evidence_version.desc(),
            evaluation_as_of.desc(),
        ),
        Index(
            "ix_incident_risk_scores_priority_calc",
            "priority_band",
            calculated_at.desc(),
        ),
    )
