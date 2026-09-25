"""
AttackChain model.

Stores the output of the attack-chain reconstruction module (Phase 8).
For each Incident, a single AttackChain is produced that orders the
correlated events into kill-chain stages mapped to the MITRE ATT&CK
framework.

``chain_steps`` is a JSON array of step objects.  Each step has:
  {
    "step_index":  int,
    "timestamp":   ISO-8601 string,
    "event_id":    UUID of the NormalizedEvent,
    "tactic_id":   MITRE tactic ID, e.g. "TA0001",
    "tactic_name": human-readable tactic name,
    "technique_ids": ["T1059", ...],
    "description": str,
    "confidence":  float 0-1
  }

This structure is deliberately stored as JSONB rather than normalised rows
because the schema evolves rapidly during development and the entire chain
is almost always read as a unit.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import DateTime, Float, ForeignKey, Integer, String, Text
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .base import Base, TimestampMixin, UUIDPrimaryKeyMixin


class AttackChain(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """Kill-chain reconstruction for one Incident."""

    __tablename__ = "attack_chains"

    # ── Parent incident ───────────────────────────────────────────────────────
    incident_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("incidents.id", ondelete="CASCADE"),
        unique=True,   # one chain per incident
        nullable=False,
        index=True,
    )

    # ── Chain data ────────────────────────────────────────────────────────────
    # Ordered list of ChainStep dicts (see module docstring).
    chain_steps: Mapped[list] = mapped_column(
        JSONB, nullable=False, default=list
    )

    # Highest-level kill-chain stage reached (e.g. "Exfiltration").
    highest_tactic: Mapped[str | None] = mapped_column(String(128), nullable=True)

    # Overall confidence of the reconstruction (0.0 – 1.0).
    # Legacy compatibility mirror only: ordinal deterministic summary evidence-strength score [0.0, 1.0]; not a probability.
    confidence: Mapped[float | None] = mapped_column(Float, nullable=True)

    # ── Phase 7 Additive ──────────────────────────────────────────────────────
    chain_version_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("attack_chain_versions.id", ondelete="SET NULL"),
        nullable=True
    )
    evidence_version: Mapped[int | None] = mapped_column(
        Integer, nullable=True
    )

    # Natural-language summary of the chain produced by the recommender.
    summary: Mapped[str | None] = mapped_column(Text, nullable=True)

    # When the chain was last recalculated.
    last_calculated_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    # ── Relationships ─────────────────────────────────────────────────────────
    incident: Mapped["Incident"] = relationship(  # noqa: F821
        "Incident", back_populates="attack_chain"
    )

    def __repr__(self) -> str:
        steps = len(self.chain_steps) if self.chain_steps else 0
        return (
            f"<AttackChain id={self.id!s:.8} "
            f"incident={self.incident_id!s:.8} "
            f"steps={steps} "
            f"confidence={self.confidence}>"
        )
