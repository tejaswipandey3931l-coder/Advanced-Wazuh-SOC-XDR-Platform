"""
NormalizedEvent model.

Represents a RawAlert that has been parsed and mapped to the platform's
common event schema.  Designed to be source-agnostic: a Wazuh agent alert,
a Zeek conn.log entry, and a Suricata EVE event all produce a
``NormalizedEvent`` with the same field set.

Fields follow the Elastic Common Schema (ECS) naming conventions where
applicable, to ease future cross-source analytics.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import (
    Boolean,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
)
from sqlalchemy.dialects.postgresql import ARRAY, JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .base import Base, TimestampMixin, UUIDPrimaryKeyMixin


class NormalizedEvent(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """Source-agnostic normalised representation of a security event."""

    __tablename__ = "normalized_events"

    # ── Source linkage ────────────────────────────────────────────────────────
    raw_alert_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("raw_alerts.id", ondelete="CASCADE"),
        unique=True,
        nullable=False,
        index=True,
    )

    # ── Timing ───────────────────────────────────────────────────────────────
    event_timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, index=True
    )

    # ── Source classification ─────────────────────────────────────────────────
    source_type: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
        index=True,
        comment="e.g. wazuh_agent, zeek, suricata, syslog",
    )
    normalization_version: Mapped[str] = mapped_column(
        String(16),
        nullable=False,
        server_default="2.0.0",
        comment="Schema normalization version (e.g. 2.0.0)",
    )
    decoder_name: Mapped[str | None] = mapped_column(
        String(64), nullable=True, index=True, comment="Wazuh decoder name"
    )
    wazuh_index_id: Mapped[str | None] = mapped_column(
        String(128), nullable=True, index=True, comment="Source OpenSearch document _id"
    )
    wazuh_index: Mapped[str | None] = mapped_column(
        String(128), nullable=True, comment="Source OpenSearch index name"
    )

    # ── Network context ───────────────────────────────────────────────────────
    src_ip: Mapped[str | None] = mapped_column(String(45), nullable=True, index=True)
    dst_ip: Mapped[str | None] = mapped_column(String(45), nullable=True, index=True)
    src_port: Mapped[int | None] = mapped_column(Integer, nullable=True)
    dst_port: Mapped[int | None] = mapped_column(Integer, nullable=True)
    network_protocol: Mapped[str | None] = mapped_column(String(16), nullable=True)

    # ── Identity context ──────────────────────────────────────────────────────
    user: Mapped[str | None] = mapped_column(String(255), nullable=True, index=True)
    hostname: Mapped[str | None] = mapped_column(
        String(255), nullable=True, index=True
    )
    agent_id: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    agent_name: Mapped[str | None] = mapped_column(String(128), nullable=True)
    auth_action: Mapped[str | None] = mapped_column(String(32), nullable=True)
    auth_result: Mapped[str | None] = mapped_column(String(16), nullable=True)

    # ── Web & Resource Context ───────────────────────────────────────────────
    domain: Mapped[str | None] = mapped_column(String(255), nullable=True)
    url: Mapped[str | None] = mapped_column(Text, nullable=True)

    # ── Process context ────────────────────────────────────────────────────────
    process_name: Mapped[str | None] = mapped_column(String(255), nullable=True)
    process_pid: Mapped[int | None] = mapped_column(Integer, nullable=True)
    process_command_line: Mapped[str | None] = mapped_column(Text, nullable=True)

    # ── File context ──────────────────────────────────────────────────────────
    file_path: Mapped[str | None] = mapped_column(Text, nullable=True)
    file_hash_md5: Mapped[str | None] = mapped_column(String(32), nullable=True)
    file_hash_sha256: Mapped[str | None] = mapped_column(String(64), nullable=True)

    # ── Event classification ──────────────────────────────────────────────────
    event_category: Mapped[str | None] = mapped_column(
        String(64), nullable=True, index=True, comment="High-level category"
    )
    event_type: Mapped[str] = mapped_column(
        String(128), nullable=False, index=True
    )
    severity: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        comment="Wazuh rule level 1-16 or normalised equivalent",
    )
    rule_id: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    rule_description: Mapped[str | None] = mapped_column(Text, nullable=True)

    # ── MITRE ATT&CK (populated by Phase 5 mapper) ────────────────────────────
    mitre_technique_ids: Mapped[list[str] | None] = mapped_column(
        ARRAY(String), nullable=True
    )
    mitre_tactic_ids: Mapped[list[str] | None] = mapped_column(
        ARRAY(String), nullable=True
    )

    # ── Enrichment flags (set by later pipeline stages) ───────────────────────
    ioc_matched: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    threat_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    ml_score: Mapped[float | None] = mapped_column(Float, nullable=True)

    # ── Overflow / extensibility ──────────────────────────────────────────────
    extra_fields: Mapped[dict | None] = mapped_column(
        JSONB,
        nullable=True,
        comment="Any source-specific fields not covered by schema columns",
    )

    # ── Relationships ─────────────────────────────────────────────────────────
    raw_alert: Mapped["RawAlert"] = relationship(  # noqa: F821
        "RawAlert", back_populates="normalized_event"
    )
    threat_intel_results: Mapped[list["ThreatIntelResult"]] = relationship(  # noqa: F821
        "ThreatIntelResult", back_populates="normalized_event", cascade="all, delete-orphan"
    )

    # ── Composite indexes ─────────────────────────────────────────────────────
    __table_args__ = (
        Index("ix_ne_src_ip_ts", "src_ip", "event_timestamp"),
        Index("ix_ne_user_host", "user", "hostname"),
        Index("ix_ne_agent_ts", "agent_id", "event_timestamp"),
    )

    def __repr__(self) -> str:
        return (
            f"<NormalizedEvent id={self.id!s:.8} "
            f"type={self.event_type!r} "
            f"severity={self.severity}>"
        )
