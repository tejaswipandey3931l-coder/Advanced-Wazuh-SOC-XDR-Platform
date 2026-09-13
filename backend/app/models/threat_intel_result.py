"""
ThreatIntelResult model.

Records the result of a threat-intelligence IOC lookup for a specific
NormalizedEvent, Incident, or ad-hoc observable query. Results are cached
in Redis and persisted here as auditable security evidence.

Populated by the ThreatIntelService in Phase 4.
Append-only semantics at the application/service layer: historical records
are never updated or deleted by normal Phase 4 workflows.
"""

from __future__ import annotations

import enum
import uuid
from datetime import datetime

from sqlalchemy import Boolean, DateTime, Enum, Float, ForeignKey, Index, String, Text
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
    VIRUSTOTAL = "virustotal"
    ALIENVAULT_OTX = "alienvault_otx"


class ThreatIntelResult(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """Result of a CTI IOC lookup for an observable (optionally linked to event/incident)."""

    __tablename__ = "threat_intel_results"

    # ── Parent event (optional) ───────────────────────────────────────────────
    normalized_event_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("normalized_events.id", ondelete="CASCADE"),
        index=True,
        nullable=True,
    )

    # ── Correlated incident (optional) ────────────────────────────────────────
    incident_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("incidents.id", ondelete="CASCADE"),
        index=True,
        nullable=True,
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
    verdict: Mapped[str] = mapped_column(String(32), nullable=False, default="unknown", server_default="unknown")
    severity: Mapped[str | None] = mapped_column(String(32), nullable=True)

    # General / legacy confidence field
    confidence: Mapped[float | None] = mapped_column(Float, nullable=True)
    # Native provider-reported confidence (e.g. AbuseIPDB abuseConfidenceScore / 100)
    provider_confidence: Mapped[float | None] = mapped_column(Float, nullable=True)
    # Derived heuristic confidence (uncalibrated heuristic, e.g. VirusTotal engine ratio)
    derived_heuristic_confidence: Mapped[float | None] = mapped_column(Float, nullable=True)

    # Human-readable category, e.g. "malware", "phishing", "scanner"
    threat_type: Mapped[str | None] = mapped_column(String(128), nullable=True)

    # Semantically preserved enrichment payload from CTI source
    context: Mapped[dict | None] = mapped_column(JSONB, nullable=True)

    # Exact raw response text for forensic verification
    raw_response_text: Mapped[str | None] = mapped_column(Text, nullable=True)

    # External reference (report URL, pulse ID, etc.)
    source_reference: Mapped[str | None] = mapped_column(String(256), nullable=True)

    # ── Cache & Lookup Timestamps ──────────────────────────────────────────────
    queried_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    cache_expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, index=True
    )

    # ── Relationships ─────────────────────────────────────────────────────────
    normalized_event: Mapped["NormalizedEvent | None"] = relationship(  # noqa: F821
        "NormalizedEvent",
        back_populates="threat_intel_results",
        foreign_keys=[normalized_event_id],
    )
    incident: Mapped["Incident | None"] = relationship(  # noqa: F821
        "Incident",
        back_populates="threat_intel_results",
        foreign_keys=[incident_id],
    )

    # ── Composite indexes ──────────────────────────────────────────────────────
    __table_args__ = (
        Index("ix_ti_ioc_source", "ioc_value", "source"),
        Index("ix_ti_event_matched", "normalized_event_id", "matched"),
        Index("ix_ti_ioc_source_queried", "ioc_value", "source", queried_at.desc()),
        Index("ix_ti_incident_id", "incident_id"),
    )

    def __repr__(self) -> str:
        return (
            f"<ThreatIntelResult id={self.id!s:.8} "
            f"ioc={self.ioc_value!r} "
            f"source={self.source.value!r} "
            f"verdict={self.verdict!r} "
            f"matched={self.matched}>"
        )
