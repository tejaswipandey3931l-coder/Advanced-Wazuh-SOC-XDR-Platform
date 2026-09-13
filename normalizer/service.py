"""
Normalization persistence service.

Orchestrates the ingestion-to-normalization pipeline:
  RawAlertItem -> RawAlert persistence -> EventNormalizer -> NormalizedEvent persistence -> Atomic commit.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any
import uuid

import structlog
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from backend.app.models.normalized_event import NormalizedEvent
from backend.app.models.raw_alert import RawAlert
from backend.app.schemas.wazuh import RawAlertItem
from normalizer.exceptions import NormalizationError
from normalizer.schemas import NormalizationResult, NormalizedEventSchema
from normalizer.wazuh_normalizer import EventNormalizer

logger = structlog.get_logger(__name__)


class NormalizationService:
    """Service for persisting normalized events and linking them to raw alerts."""

    def __init__(self, normalizer: EventNormalizer | None = None) -> None:
        self.normalizer = normalizer or EventNormalizer()

    async def _get_or_create_raw_alert(
        self,
        db: AsyncSession,
        item: RawAlertItem,
    ) -> RawAlert:
        """Resolve or persist RawAlert row, returning existing or new instance."""
        stmt = select(RawAlert).where(RawAlert.wazuh_index_id == item.id)
        result = await db.execute(stmt)
        existing = result.scalar_one_or_none()
        if existing:
            return existing

        # Parse rule_id to integer if numeric
        rule_id_int: int | None = None
        if item.rule_id is not None:
            try:
                rule_id_int = int(item.rule_id)
            except (ValueError, TypeError):
                rule_id_int = None

        # Parse timestamp
        wazuh_ts: datetime | None = None
        raw_dict = item.raw or {}
        raw_ts = raw_dict.get("timestamp") or raw_dict.get("@timestamp") or item.timestamp
        if raw_ts:
            try:
                wazuh_ts = self.normalizer._parse_timestamp(raw_ts)
            except Exception:
                wazuh_ts = None

        raw_alert = RawAlert(
            wazuh_index_id=item.id,
            agent_id=str(item.agent_id) if item.agent_id else None,
            agent_name=item.agent_name,
            rule_id=rule_id_int,
            rule_level=item.rule_level,
            rule_description=item.rule_description,
            wazuh_timestamp=wazuh_ts,
            raw_json=raw_dict,
            is_normalized=False,
        )
        db.add(raw_alert)
        await db.flush()
        return raw_alert

    async def process_and_store(
        self,
        db: AsyncSession,
        item: RawAlertItem | dict[str, Any],
    ) -> NormalizedEventSchema:
        """Normalize a single alert, persist RawAlert and NormalizedEvent, and return schema.

        Guarantees idempotent execution: if event already exists, updates in-place.
        """
        if isinstance(item, dict):
            raw_dict = item.get("raw") or item
            item_obj = RawAlertItem(
                id=item["id"],
                index=item["index"],
                timestamp=item.get("timestamp"),
                rule_id=item.get("rule_id"),
                rule_level=item.get("rule_level"),
                rule_description=item.get("rule_description"),
                agent_id=item.get("agent_id"),
                agent_name=item.get("agent_name"),
                raw=raw_dict,
            )
        else:
            item_obj = item

        # 1. Resolve or create RawAlert in PostgreSQL
        raw_alert = await self._get_or_create_raw_alert(db, item_obj)

        # 2. Pure normalization with linkage to RawAlert
        schema = self.normalizer.normalize_alert(
            item=item_obj,
            ingestion_timestamp=raw_alert.created_at,
            raw_alert_id=raw_alert.id,
        )

        # 3. Check for existing NormalizedEvent by event_id or raw_alert_id
        stmt = select(NormalizedEvent).where(
            (NormalizedEvent.id == schema.event_id)
            | (NormalizedEvent.raw_alert_id == raw_alert.id)
        )
        result = await db.execute(stmt)
        existing_event = result.scalar_one_or_none()

        if existing_event:
            # Update existing event fields (idempotent update)
            existing_event.event_timestamp = schema.event_timestamp
            existing_event.source_type = schema.source_type
            existing_event.normalization_version = schema.normalization_version
            existing_event.decoder_name = schema.decoder_name
            existing_event.wazuh_index_id = schema.wazuh_index_id
            existing_event.wazuh_index = schema.wazuh_index
            existing_event.event_category = schema.event_category
            existing_event.event_type = schema.event_type
            existing_event.severity = schema.severity
            existing_event.rule_id = schema.rule_id
            existing_event.rule_description = schema.rule_description
            existing_event.mitre_technique_ids = schema.mitre_technique_ids
            existing_event.mitre_tactic_ids = schema.mitre_tactic_ids
            existing_event.agent_id = schema.agent_id
            existing_event.agent_name = schema.agent_name
            existing_event.hostname = schema.hostname
            existing_event.src_ip = schema.src_ip
            existing_event.dst_ip = schema.dst_ip
            existing_event.src_port = schema.src_port
            existing_event.dst_port = schema.dst_port
            existing_event.network_protocol = schema.network_protocol
            existing_event.user = schema.user
            existing_event.auth_action = schema.auth_action
            existing_event.auth_result = schema.auth_result
            existing_event.domain = schema.domain
            existing_event.url = schema.url
            existing_event.process_name = schema.process_name
            existing_event.process_pid = schema.process_pid
            existing_event.process_command_line = schema.process_command_line
            existing_event.file_path = schema.file_path
            existing_event.file_hash_md5 = schema.file_hash_md5
            existing_event.file_hash_sha256 = schema.file_hash_sha256
            existing_event.extra_fields = schema.extra_fields
        else:
            # Create new NormalizedEvent
            new_event = NormalizedEvent(
                id=schema.event_id,
                raw_alert_id=raw_alert.id,
                event_timestamp=schema.event_timestamp,
                source_type=schema.source_type,
                normalization_version=schema.normalization_version,
                decoder_name=schema.decoder_name,
                wazuh_index_id=schema.wazuh_index_id,
                wazuh_index=schema.wazuh_index,
                event_category=schema.event_category,
                event_type=schema.event_type,
                severity=schema.severity,
                rule_id=schema.rule_id,
                rule_description=schema.rule_description,
                mitre_technique_ids=schema.mitre_technique_ids,
                mitre_tactic_ids=schema.mitre_tactic_ids,
                agent_id=schema.agent_id,
                agent_name=schema.agent_name,
                hostname=schema.hostname,
                src_ip=schema.src_ip,
                dst_ip=schema.dst_ip,
                src_port=schema.src_port,
                dst_port=schema.dst_port,
                network_protocol=schema.network_protocol,
                user=schema.user,
                auth_action=schema.auth_action,
                auth_result=schema.auth_result,
                domain=schema.domain,
                url=schema.url,
                process_name=schema.process_name,
                process_pid=schema.process_pid,
                process_command_line=schema.process_command_line,
                file_path=schema.file_path,
                file_hash_md5=schema.file_hash_md5,
                file_hash_sha256=schema.file_hash_sha256,
                extra_fields=schema.extra_fields,
            )
            db.add(new_event)

        # 4. Mark raw alert as normalized
        raw_alert.is_normalized = True
        await db.commit()

        return schema

    async def process_batch(
        self,
        db: AsyncSession,
        items: list[RawAlertItem | dict[str, Any]],
    ) -> list[NormalizationResult]:
        """Normalize a batch of alerts, saving valid ones and recording individual errors."""
        results: list[NormalizationResult] = []
        for item in items:
            doc_id: str | None = None
            if isinstance(item, dict):
                doc_id = item.get("id")
            elif isinstance(item, RawAlertItem):
                doc_id = item.id

            try:
                # Use a nested transaction/savepoint for each alert
                async with db.begin_nested():
                    schema = await self.process_and_store(db, item)
                results.append(
                    NormalizationResult(
                        success=True,
                        event=schema,
                        error=None,
                        wazuh_index_id=doc_id,
                    )
                )
            except Exception as exc:
                logger.warning(
                    "normalization_service_batch_item_failed",
                    wazuh_index_id=doc_id,
                    error=str(exc),
                    error_type=type(exc).__name__,
                )
                results.append(
                    NormalizationResult(
                        success=False,
                        event=None,
                        error=f"{type(exc).__name__}: {exc}",
                        wazuh_index_id=doc_id,
                    )
                )
        return results
