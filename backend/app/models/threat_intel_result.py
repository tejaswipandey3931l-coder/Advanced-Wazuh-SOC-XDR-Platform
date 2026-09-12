"""
ThreatIntelResult model.

Records the result of a threat-intelligence IOC lookup for a specific
NormalizedEvent.  Results are cached here so that repeated lookups for the
same indicator do not hit external CTI APIs unnecessarily.

Populated by the ThreatIntelService in Phase 4.
"""

from __future__ import annotations

import enum
import uuid
from datetime import datetime

from sqlalchemy import Boolean, DateTime, Enum, Float, ForeignKey, Index, String
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .base import Base, TimestampMixin, UUIDPrimaryKeyMixin


class IOCType(str, enum.Enum):
    IP = "ip"
    DOMAIN = "domain"
    URL = "url"
    FILE_HASH = "file_hash"
    EMAIL = "email"


class CTISource(str, enum.Enum):
    ABUSEIPDB = "abuseipdb"
    MISP = "misp"
    OPENCTI = "opencti"
    LOCAL_FEED = "local_feed"


class ThreatIntelResult(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """Result of a CTI IOC lookup for one NormalizedEvent."""

    __tablename__ = "threat_intel_results"

    # ── Parent event ─────────────────────────────────────────────────────────
    normalized_event_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("normalized_events.id", ondelete="CASCADE"),
        index=True,
        nullable=False,
    )

    # ── IOC details ───────────────────────────────────────────────────────────
    ioc_type: Mapped[IOCType] = mapped_column(
        Enum(
            IOCType,
            name="ioc_type",
            values_callable=lambda x: [e.value for e in x],
        ),
        nullable=False,
    )
    ioc_value: Mapped[str] = mapped_column(String(512), nullable=False, index=True)

    # ── Lookup metadata ────────────────────────────────────────────────────────
    source: Mapped[CTISource] = mapped_column(
        Enum(
            CTISource,
            name="cti_source",
            values_callable=lambda x: [e.value for e in x],
        ),
        nullable=False,
    )
    matched: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    confidence: Mapped[float | None] = mapped_column(Float, nullable=True)

    # Human-readable category, e.g. "malware", "phishing", "scanner"
    threat_type: Mapped[str | None] = mapped_column(String(128), nullable=True)

    # Raw enrichment payload from the CTI source.
    context: Mapped[dict | None] = mapped_column(JSONB, nullable=True)

    # ── Cache TTL ──────────────────────────────────────────────────────────────
    queried_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    cache_expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, index=True
    )

    # ── Relationships ─────────────────────────────────────────────────────────
    normalized_event: Mapped["NormalizedEvent"] = relationship(  # noqa: F821
        "NormalizedEvent",
        back_populates="threat_intel_results",
        foreign_keys=[normalized_event_id],
    )

    # ── Composite indexes ──────────────────────────────────────────────────────
    __table_args__ = (
        Index("ix_ti_ioc_source", "ioc_value", "source"),
        Index("ix_ti_event_matched", "normalized_event_id", "matched"),
    )

    def __repr__(self) -> str:
        return (
            f"<ThreatIntelResult id={self.id!s:.8} "
            f"ioc={self.ioc_value!r} "
            f"source={self.source.value!r} "
            f"matched={self.matched}>"
        )
