"""
RawAlert model.

Stores the original, un-modified alert JSON ingested from the Wazuh
OpenSearch index (``wazuh-alerts-*``).  Nothing is altered during ingestion
— this table is an append-only audit record of what Wazuh produced.

Processed (normalised) data lives in ``NormalizedEvent``.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import Boolean, DateTime, Index, Integer, String, Text, func
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .base import Base, TimestampMixin, UUIDPrimaryKeyMixin


class RawAlert(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """One-to-one record of a Wazuh alert as received from OpenSearch."""

    __tablename__ = "raw_alerts"

    # ── Wazuh identifiers ────────────────────────────────────────────────────
    # The _id field from the OpenSearch document.
    wazuh_index_id: Mapped[str] = mapped_column(
        String(255),
        unique=True,
        index=True,
        nullable=False,
        comment="OpenSearch document _id for this alert",
    )

    # ── Agent ────────────────────────────────────────────────────────────────
    agent_id: Mapped[str | None] = mapped_column(
        String(64), index=True, nullable=True
    )
    agent_name: Mapped[str | None] = mapped_column(String(255), nullable=True)

    # ── Rule ─────────────────────────────────────────────────────────────────
    rule_id: Mapped[int | None] = mapped_column(Integer, index=True, nullable=True)
    rule_level: Mapped[int | None] = mapped_column(Integer, nullable=True)
    rule_description: Mapped[str | None] = mapped_column(Text, nullable=True)

    # ── Timing ───────────────────────────────────────────────────────────────
    # Timestamp as reported by Wazuh (UTC).
    wazuh_timestamp: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), index=True, nullable=True
    )

    # ── Full payload ─────────────────────────────────────────────────────────
    # The complete alert JSON from OpenSearch, stored verbatim.
    raw_json: Mapped[dict] = mapped_column(
        JSONB, nullable=False, comment="Complete alert JSON from wazuh-alerts-* index"
    )

    # ── Processing state ──────────────────────────────────────────────────────
    is_normalized: Mapped[bool] = mapped_column(
        Boolean, default=False, nullable=False, index=True
    )

    # ── Relationships ─────────────────────────────────────────────────────────
    # Populated when the event is normalised (Phase 2).
    normalized_event: Mapped["NormalizedEvent | None"] = relationship(  # noqa: F821
        "NormalizedEvent", back_populates="raw_alert", uselist=False
    )

    # ── Composite indexes ─────────────────────────────────────────────────────
    __table_args__ = (
        Index("ix_raw_alerts_agent_ts", "agent_id", "wazuh_timestamp"),
        Index("ix_raw_alerts_rule_level", "rule_level"),
    )

    def __repr__(self) -> str:
        return (
            f"<RawAlert id={self.id!s:.8} "
            f"wazuh_index_id={self.wazuh_index_id!r} "
            f"rule_id={self.rule_id}>"
        )
