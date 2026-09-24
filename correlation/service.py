"""
Correlation Persistence Service.

Coordinates the pure CorrelationEngine with PostgreSQL persistence:
  - Manages active incident deduplication with PostgreSQL partial unique index
  - Enforces atomic incident lifecycle transitions (inactivity expiration -> CLOSED)
  - Links evidence into incident_events with strict idempotency
"""

from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from typing import Any
from uuid import UUID

import structlog
from sqlalchemy import func, select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from backend.app.models.correlation_rule import CorrelationRule
from backend.app.models.incident import Incident, IncidentStatus, IncidentSeverity
from backend.app.models.incident_event import IncidentEvent
from backend.app.models.normalized_event import NormalizedEvent
from .engine import CorrelationEngine
from .models import CorrelationMatch

logger = structlog.get_logger(__name__)


def generate_dedup_key(rule_id: UUID, entity_field: str, entity_value: str) -> str:
    """Computes a deterministic SHA256 deduplication key from stable rule and entity identity."""
    raw = f"{rule_id}:{entity_field}:{entity_value}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


class CorrelationService:
    """High-level service managing correlation engine evaluation and database persistence."""

    def __init__(
        self,
        engine: CorrelationEngine,
        t_inactivity_seconds: int = 3600,
    ) -> None:
        self.engine = engine
        self.t_inactivity_seconds = t_inactivity_seconds

    async def process_normalized_event(
        self,
        db: AsyncSession,
        event: NormalizedEvent,
    ) -> list[Incident]:
        """
        Ingests a NormalizedEvent into the correlation engine and persists any resultant Incidents.
        Returns a list of created or updated active Incident records.
        """
        # Build dictionary representation of event fields for rule evaluation
        event_dict = {
            "event_type": event.event_type,
            "event_category": event.event_category,
            "severity": event.severity,
            "rule_id": event.rule_id,
            "source_type": event.source_type,
            "src_ip": event.src_ip,
            "dst_ip": event.dst_ip,
            "src_port": event.src_port,
            "dst_port": event.dst_port,
            "user": event.user,
            "hostname": event.hostname,
            "agent_id": event.agent_id,
            "agent_name": event.agent_name,
            "auth_action": event.auth_action,
            "auth_result": event.auth_result,
            "process_name": event.process_name,
            "file_path": event.file_path,
        }
        if event.extra_fields:
            event_dict.update(event.extra_fields)

        ing_ts = getattr(event, "ingestion_timestamp", None) or getattr(event, "created_at", None)
        matches = await self.engine.evaluate_event(
            event_id=event.id,
            event_dict=event_dict,
            event_timestamp=event.event_timestamp,
            ingestion_timestamp=ing_ts,
        )

        if not matches:
            return []

        incidents: list[Incident] = []
        for match in matches:
            incident = await self.persist_correlation_match(db, match)
            incidents.append(incident)

        return incidents

    async def get_or_create_active_incident(
        self,
        db: AsyncSession,
        dedup_key: str,
        match: CorrelationMatch,
    ) -> tuple[Incident, bool]:
        """
        Atomically resolves, aggregates, or creates an active incident under concurrent execution.
        Enforces that PostgreSQL permits at most one active incident for a given dedup_key.
        Transitions expired incidents to CLOSED when last_seen exceeds t_inactivity_seconds.
        Returns (incident, created_flag).
        """
        # Ensure CorrelationRule exists in database via atomic upsert
        if match.rule and match.rule.id:
            rule_insert_stmt = pg_insert(CorrelationRule).values(
                id=match.rule.id,
                name=match.rule.name,
                description=match.rule.description,
                rule_type=match.rule.rule_type,
                severity=match.rule.severity.value,
                base_confidence=match.rule.base_confidence,
                time_window_seconds=match.rule.time_window_seconds,
                min_event_count=match.rule.min_event_count,
                entity_field=match.rule.entity_field,
                conditions=match.rule.conditions,
                is_active=match.rule.is_active,
                priority=match.rule.priority,
                version=match.rule.version,
                mitre_technique_id=match.rule.mitre_technique_id,
                mitre_tactic_id=match.rule.mitre_tactic_id,
            ).on_conflict_do_nothing()
            await db.execute(rule_insert_stmt)
            await db.flush()

        # 1. Lock existing active incident for this dedup_key (status OPEN or INVESTIGATING)
        stmt = (
            select(Incident)
            .where(
                Incident.dedup_key == dedup_key,
                Incident.status.in_([IncidentStatus.OPEN, IncidentStatus.INVESTIGATING]),
            )
            .with_for_update()
        )
        result = await db.execute(stmt)
        incident = result.scalar_one_or_none()

        if incident:
            # Check inactivity elapsed time relative to the incoming match
            elapsed_inactivity = (match.first_seen - incident.last_seen).total_seconds()

            if elapsed_inactivity <= self.t_inactivity_seconds:
                # Active incident is within inactivity window: aggregate into existing incident
                return incident, False

            # Inactivity timeout exceeded: Expired incident must no longer block new incident creation.
            # Transition expired incident to non-active status using existing IncidentStatus model:
            incident.status = IncidentStatus.CLOSED
            incident.description = (
                (incident.description or "")
                + f"\n[System] Automatically closed due to inactivity timeout ({int(elapsed_inactivity)}s > {self.t_inactivity_seconds}s) before new incident creation."
            )
            # Flush state to database so this row no longer satisfies partial unique index WHERE clause:
            await db.flush()
            logger.info(
                "active_incident_expired_and_closed",
                incident_id=str(incident.id),
                dedup_key=dedup_key,
                elapsed_seconds=elapsed_inactivity,
            )

        # 2. At this point, no active incident exists for this dedup_key in PostgreSQL.
        # Create new active Incident in a nested savepoint to handle any concurrent race conditions.
        try:
            async with db.begin_nested():
                new_incident = Incident(
                    title=match.rule.name,
                    description=match.rule.description,
                    status=IncidentStatus.OPEN,
                    severity=match.rule.severity,
                    first_seen=match.first_seen,
                    last_seen=match.last_seen,
                    alert_count=0,  # Updated when member events are linked
                    correlation_rule_id=match.rule.id,
                    confidence=match.confidence,
                    dedup_key=dedup_key,
                    entity_context={match.entity_field: match.entity_value},
                    mitre_techniques=match.mitre_techniques,
                    mitre_tactics=match.mitre_tactics,
                )
                db.add(new_incident)
                await db.flush()
                logger.info(
                    "new_active_incident_created",
                    incident_id=str(new_incident.id),
                    rule_name=match.rule.name,
                    dedup_key=dedup_key,
                )
                return new_incident, True
        except IntegrityError:
            # 3. Concurrent worker won the insert race: rollback savepoint and select the active winner
            result = await db.execute(stmt)
            incident = result.scalar_one_or_none()
            if incident is not None:
                return incident, False
            raise

    async def persist_correlation_match(
        self,
        db: AsyncSession,
        match: CorrelationMatch,
    ) -> Incident:
        """
        Persists a CorrelationMatch:
          1. Resolves active Incident (or creates new one with concurrency protection).
          2. Updates timeline, confidence, and MITRE metadata.
          3. Links member events into incident_events idempotently.
          4. Updates incident.alert_count to reflect unique linked events.
        """
        dedup_key = generate_dedup_key(match.rule.id, match.entity_field, match.entity_value)
        incident, created = await self.get_or_create_active_incident(db, dedup_key, match)

        if not created:
            # Aggregate timeline
            if match.first_seen < incident.first_seen:
                incident.first_seen = match.first_seen
            if match.last_seen > incident.last_seen:
                incident.last_seen = match.last_seen
            # Update confidence to highest observed
            incident.confidence = max(incident.confidence, match.confidence)

            # Merge MITRE context
            existing_tech = set(incident.mitre_techniques or [])
            existing_tech.update(match.mitre_techniques)
            incident.mitre_techniques = sorted(existing_tech)

            existing_tact = set(incident.mitre_tactics or [])
            existing_tact.update(match.mitre_tactics)
            incident.mitre_tactics = sorted(existing_tact)
            incident.evidence_version = (incident.evidence_version or 1) + 1

        # 4. Link member events into incident_events idempotently
        for event_id in match.matched_event_ids:
            # Check if this event is already linked to this incident
            existing_link_stmt = select(IncidentEvent).where(
                IncidentEvent.incident_id == incident.id,
                IncidentEvent.normalized_event_id == event_id,
            )
            existing_link = (await db.execute(existing_link_stmt)).scalar_one_or_none()

            if not existing_link:
                role = match.event_roles.get(event_id, "member")
                link = IncidentEvent(
                    incident_id=incident.id,
                    normalized_event_id=event_id,
                    correlation_rule_id=match.rule.id,
                    match_role=role,
                    confidence=match.confidence,
                )
                db.add(link)

        await db.flush()

        # Update alert_count based on exact unique count of linked events
        count_stmt = select(func.count(IncidentEvent.id)).where(
            IncidentEvent.incident_id == incident.id
        )
        total_alerts = (await db.execute(count_stmt)).scalar_one()
        incident.alert_count = total_alerts

        await db.flush()
        await db.refresh(incident)

        # Dispatch non-blocking background risk calculation with failure isolation
        try:
            import asyncio
            from risk_engine.service import RiskService
            asyncio.create_task(
                RiskService.evaluate_incident_background(
                    incident.id, trigger_reason="event_correlated"
                )
            )
        except Exception:
            pass

        return incident
