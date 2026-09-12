"""
AuditLog model.

Immutable audit trail for significant system events.

Every configuration change, API action, pipeline event, and security-relevant
system event is recorded here.  Rows are never updated or deleted — the table
is append-only.  This satisfies the SRS audit logging requirement and supports
the research paper's reproducibility requirement (configuration changes are
recorded with timestamps and actors).

The ``actor`` field is "system" for automated pipeline actions and the
username/service-id for human-initiated actions.
"""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import Boolean, DateTime, Index, String, Text, func
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from .base import Base, UUIDPrimaryKeyMixin


class AuditLog(UUIDPrimaryKeyMixin, Base):
    """Append-only audit record.  Never updated; never deleted."""

    __tablename__ = "audit_logs"

    # ── Timing ───────────────────────────────────────────────────────────────
    # Server-side default ensures consistency regardless of application clock.
    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
        index=True,
    )

    # ── Who ───────────────────────────────────────────────────────────────────
    # "system" for automated pipeline steps; username or service-id otherwise.
    actor: Mapped[str] = mapped_column(String(255), nullable=False, index=True)

    # ── What ──────────────────────────────────────────────────────────────────
    # Dot-namespaced action identifier, e.g. "api.health_check",
    # "incident.created", "correlation_rule.modified", "ingestion.started".
    action: Mapped[str] = mapped_column(String(255), nullable=False, index=True)

    # ── Which resource ────────────────────────────────────────────────────────
    resource_type: Mapped[str | None] = mapped_column(String(128), nullable=True)
    resource_id: Mapped[str | None] = mapped_column(String(255), nullable=True)

    # ── Details ───────────────────────────────────────────────────────────────
    # Structured payload — what changed, what was the trigger, etc.
    details: Mapped[dict | None] = mapped_column(JSONB, nullable=True)

    # ── Network context ───────────────────────────────────────────────────────
    ip_address: Mapped[str | None] = mapped_column(String(45), nullable=True)
    user_agent: Mapped[str | None] = mapped_column(Text, nullable=True)

    # ── Outcome ───────────────────────────────────────────────────────────────
    success: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)

    # ── Composite indexes ─────────────────────────────────────────────────────
    __table_args__ = (
        Index("ix_audit_actor_ts", "actor", "timestamp"),
        Index("ix_audit_action_ts", "action", "timestamp"),
        Index("ix_audit_resource", "resource_type", "resource_id"),
    )

    def __repr__(self) -> str:
        return (
            f"<AuditLog id={self.id!s:.8} "
            f"actor={self.actor!r} "
            f"action={self.action!r} "
            f"success={self.success}>"
        )
