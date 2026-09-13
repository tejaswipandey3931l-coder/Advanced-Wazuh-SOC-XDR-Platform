"""
Advanced Wazuh SOC/XDR — FastAPI application entry point.

Startup order:
  1. Logging is configured (structlog with automatic secret redaction).
  2. Application state is validated (settings loaded).
  3. Routes are registered.
  4. Application is ready to serve requests.
"""

from __future__ import annotations

from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import Any

import structlog
from fastapi import Depends, FastAPI, HTTPException, Query, Request
from fastapi.responses import JSONResponse
from uuid import UUID

from sqlalchemy import func, select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession

from .config import get_settings
from .database import get_db
from .exceptions import IntegrationError
from .logging_config import configure_logging
from .models.correlation_rule import CorrelationRule, RuleType
from .models.incident import Incident, IncidentSeverity, IncidentStatus
from .models.incident_event import IncidentEvent
from .models.normalized_event import NormalizedEvent
from .models.raw_alert import RawAlert
from .schemas.incident import (
    CorrelationRuleCreateRequest,
    CorrelationRuleResponse,
    CorrelationRulesListResponse,
    EvaluateEventRequest,
    EvaluateEventResponse,
    IncidentDetailResponse,
    IncidentEventItem,
    IncidentEventsListResponse,
    IncidentListResponse,
    IncidentResponse,
)
from .schemas.wazuh import (
    AlertListResponse,
    RawAlertItem,
    WazuhApiInfo,
    WazuhManagerInfo,
    WazuhManagerStatus,
)
from .wazuh_client import WazuhClient, WazuhIndexerClient
from correlation.engine import CorrelationEngine
from correlation.models import CorrelationRuleDefinition
from correlation.rules import RuleRegistry
from correlation.service import CorrelationService
from correlation.state import InMemoryWindowStateStore, RedisWindowStateStore, WindowStateStore
from normalizer.exceptions import NormalizationError
from normalizer.schemas import (
    NormalizedEventListResponse,
    NormalizedEventSchema,
)
from normalizer.service import NormalizationService
from normalizer.wazuh_normalizer import EventNormalizer, _map_severity_label

# ---------------------------------------------------------------------------
# Bootstrap — configure logging before anything else so that all subsequent
# imports and startup messages are captured with the correct format.
# ---------------------------------------------------------------------------
_settings = get_settings()
configure_logging(debug=_settings.app_debug)

log = structlog.get_logger(__name__)

# ── Correlation Engine & Service Setup ────────────────────────────────────────
_rule_registry = RuleRegistry()
_rule_registry.load_defaults()
_window_state_store: WindowStateStore = RedisWindowStateStore(redis_url=_settings.soc_redis_url)
_correlation_engine = CorrelationEngine(registry=_rule_registry, state_store=_window_state_store)
_correlation_service = CorrelationService(engine=_correlation_engine)


def get_correlation_service() -> CorrelationService:
    return _correlation_service


# ---------------------------------------------------------------------------
# Lifespan context manager (FastAPI 0.93+ pattern).
# ---------------------------------------------------------------------------
@asynccontextmanager
async def lifespan(app: FastAPI):
    log.info(
        "application_startup",
        name=_settings.app_name,
        version=_settings.app_version,
        debug=_settings.app_debug,
        wazuh_api_url=_settings.wazuh_api_url,
        opensearch_url=_settings.opensearch_url,
        redis_url=_settings.soc_redis_url,
    )
    if isinstance(_window_state_store, RedisWindowStateStore):
        await _window_state_store.check_health()
    yield
    if isinstance(_window_state_store, RedisWindowStateStore):
        await _window_state_store.close()
    log.info("application_shutdown")


# ---------------------------------------------------------------------------
# FastAPI application instance
# ---------------------------------------------------------------------------
app = FastAPI(
    title="Advanced Wazuh SOC",
    version=_settings.app_version,
    description=(
        "Intelligence and analytics layer built on top of Wazuh SIEM/XDR. "
        "Provides correlation, threat intelligence, ML prioritisation, "
        "attack-chain reconstruction, and response recommendations."
    ),
    lifespan=lifespan,
    # Disable docs in production; enable only in debug mode.
    docs_url="/docs" if _settings.app_debug else None,
    redoc_url="/redoc" if _settings.app_debug else None,
)


# ---------------------------------------------------------------------------
# Global Exception Handlers — ensures no credentials leak in responses
# ---------------------------------------------------------------------------
@app.exception_handler(IntegrationError)
async def integration_error_handler(request: Request, exc: IntegrationError) -> JSONResponse:
    log.error("integration_error_caught", error_type=type(exc).__name__, message=exc.message, path=request.url.path)
    return JSONResponse(
        status_code=exc.status_code,
        content={"detail": exc.message, "error_type": type(exc).__name__},
    )


@app.exception_handler(NormalizationError)
async def normalization_error_handler(request: Request, exc: NormalizationError) -> JSONResponse:
    log.warning("normalization_error_caught", error_type=type(exc).__name__, message=str(exc), path=request.url.path)
    return JSONResponse(
        status_code=422,
        content={"detail": str(exc), "error_type": type(exc).__name__},
    )


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------


@app.get(
    "/health",
    tags=["System"],
    summary="Health check",
    response_description="Service is healthy",
)
async def health() -> dict[str, Any]:
    """Return a simple liveness probe response."""
    log.debug("health_check_called")
    return {
        "status": "ok",
        "service": "advanced-wazuh-soc",
        "version": _settings.app_version,
    }


@app.get(
    "/wazuh/info",
    tags=["Wazuh"],
    summary="Wazuh REST API information",
    response_model=WazuhApiInfo,
    response_description="Wazuh REST API top-level metadata",
)
async def wazuh_info() -> WazuhApiInfo:
    """Return Wazuh API version and metadata.

    Authenticates against the Wazuh REST API and returns the top-level
    info object.  Used to verify Wazuh API connectivity.
    """
    log.info("wazuh_info_requested")
    try:
        client = WazuhClient()
        result = await client.get_api_info()
        log.info("wazuh_info_success", version=result.api_version)
        return result
    except IntegrationError:
        raise
    except Exception as exc:
        log.error("wazuh_info_unexpected_failure", error=str(exc))
        raise HTTPException(
            status_code=502,
            detail="Unexpected failure connecting to Wazuh API",
        ) from exc


@app.get(
    "/wazuh/manager",
    tags=["Wazuh"],
    summary="Wazuh Manager node metadata",
    response_model=WazuhManagerInfo,
    response_description="Wazuh manager engine version and installation details",
)
async def wazuh_manager() -> WazuhManagerInfo:
    """Return Wazuh Manager engine metadata (version, path, UUID)."""
    log.info("wazuh_manager_requested")
    try:
        client = WazuhClient()
        result = await client.get_manager_info()
        log.info("wazuh_manager_success", version=result.version)
        return result
    except IntegrationError:
        raise
    except Exception as exc:
        log.error("wazuh_manager_unexpected_failure", error=str(exc))
        raise HTTPException(
            status_code=502,
            detail="Unexpected failure retrieving Wazuh manager info",
        ) from exc


@app.get(
    "/wazuh/status",
    tags=["Wazuh"],
    summary="Wazuh daemon status",
    response_model=WazuhManagerStatus,
    response_description="Status of Wazuh core daemons",
)
async def wazuh_status() -> WazuhManagerStatus:
    """Return operational status of core Wazuh manager daemons."""
    log.info("wazuh_status_requested")
    try:
        client = WazuhClient()
        return await client.get_manager_status()
    except IntegrationError:
        raise
    except Exception as exc:
        log.error("wazuh_status_unexpected_failure", error=str(exc))
        raise HTTPException(
            status_code=502,
            detail="Unexpected failure retrieving Wazuh daemon status",
        ) from exc


@app.get(
    "/wazuh/alerts",
    tags=["Wazuh"],
    summary="Retrieve raw alerts from Wazuh Indexer",
    response_model=AlertListResponse,
    response_description="Paginated raw alerts preserving original payload",
)
async def get_alerts(
    limit: int = Query(default=20, ge=1, le=500, description="Max alerts to return (1-500)"),
    offset: int = Query(default=0, ge=0, description="Alert offset for pagination"),
    min_level: int | None = Query(default=None, ge=0, le=16, description="Filter by minimum rule level (0-16)"),
    rule_id: str | None = Query(default=None, description="Filter by exact rule ID"),
    agent_id: str | None = Query(default=None, description="Filter by agent ID"),
    start_time: datetime | None = Query(default=None, description="Start timestamp filter (ISO-8601)"),
    end_time: datetime | None = Query(default=None, description="End timestamp filter (ISO-8601)"),
) -> AlertListResponse:
    """Retrieve raw Wazuh alerts from Wazuh Indexer (OpenSearch).

    Guarantees:
      - Bounded pagination with valid total count.
      - Full preservation of the original Wazuh alert JSON payload under ``raw``.
      - Safe handling of zero-result queries as successful responses.
      - Decoupled error reporting without leaking infrastructure credentials.
    """
    log.info("wazuh_alerts_requested", limit=limit, offset=offset, min_level=min_level, rule_id=rule_id)
    try:
        client = WazuhIndexerClient()
        start_iso = start_time.isoformat() if start_time else None
        end_iso = end_time.isoformat() if end_time else None

        result = await client.get_alerts(
            limit=limit,
            offset=offset,
            min_level=min_level,
            rule_id=rule_id,
            agent_id=agent_id,
            start_time=start_iso,
            end_time=end_iso,
        )
        log.info("wazuh_alerts_success", count=result.count, total=result.total)
        return result
    except IntegrationError:
        raise
    except Exception as exc:
        log.error("wazuh_alerts_unexpected_failure", error=str(exc))
        raise HTTPException(
            status_code=502,
            detail="Unexpected failure querying Wazuh Indexer",
        ) from exc


# ---------------------------------------------------------------------------
# Phase 2 Normalization Endpoints
# ---------------------------------------------------------------------------


@app.post(
    "/normalizer/normalize",
    tags=["Normalizer"],
    summary="Normalize a raw alert",
    response_model=NormalizedEventSchema,
    response_description="Normalized and ECS-mapped event schema",
)
async def normalize_alert_endpoint(
    alert: RawAlertItem,
    persist: bool = Query(default=True, description="Whether to persist raw alert and normalized event in database"),
    db: AsyncSession = Depends(get_db),
) -> NormalizedEventSchema:
    """Normalize a Wazuh raw alert into the standard ECS-aligned NormalizedEvent schema.

    If ``persist=True`` (default), persists the RawAlert and NormalizedEvent in PostgreSQL
    with atomic linkage. If ``persist=False``, performs in-memory normalization without DB writes.
    """
    log.info("normalize_alert_requested", alert_id=alert.id, index=alert.index, persist=persist)
    try:
        if persist:
            service = NormalizationService()
            return await service.process_and_store(db, alert)
        else:
            normalizer = EventNormalizer()
            return normalizer.normalize_alert(alert)
    except NormalizationError:
        raise
    except Exception as exc:
        log.error("normalize_alert_unexpected_error", error=str(exc), alert_id=alert.id)
        raise HTTPException(
            status_code=500,
            detail=f"Failed to normalize alert: {exc}",
        ) from exc


@app.get(
    "/events/normalized",
    tags=["Normalizer"],
    summary="List normalized events",
    response_model=NormalizedEventListResponse,
    response_description="Paginated normalized events from PostgreSQL",
)
async def get_normalized_events(
    limit: int = Query(default=20, ge=1, le=500, description="Max events to return (1-500)"),
    offset: int = Query(default=0, ge=0, description="Offset for pagination"),
    category: str | None = Query(default=None, description="Filter by event_category"),
    event_type: str | None = Query(default=None, description="Filter by event_type"),
    min_severity: int | None = Query(default=None, ge=1, le=16, description="Filter by minimum severity (1-16)"),
    rule_id: str | None = Query(default=None, description="Filter by rule ID"),
    agent_id: str | None = Query(default=None, description="Filter by agent ID"),
    db: AsyncSession = Depends(get_db),
) -> NormalizedEventListResponse:
    """Query normalized events stored in PostgreSQL with filtering and pagination."""
    log.info(
        "get_normalized_events_requested",
        limit=limit,
        offset=offset,
        category=category,
        event_type=event_type,
        min_severity=min_severity,
        rule_id=rule_id,
        agent_id=agent_id,
    )
    try:
        stmt = (
            select(NormalizedEvent, RawAlert.raw_json)
            .join(RawAlert, NormalizedEvent.raw_alert_id == RawAlert.id, isouter=True)
        )
        count_stmt = select(func.count(NormalizedEvent.id))

        if category:
            stmt = stmt.where(NormalizedEvent.event_category == category)
            count_stmt = count_stmt.where(NormalizedEvent.event_category == category)
        if event_type:
            stmt = stmt.where(NormalizedEvent.event_type == event_type)
            count_stmt = count_stmt.where(NormalizedEvent.event_type == event_type)
        if min_severity is not None:
            stmt = stmt.where(NormalizedEvent.severity >= min_severity)
            count_stmt = count_stmt.where(NormalizedEvent.severity >= min_severity)
        if rule_id:
            stmt = stmt.where(NormalizedEvent.rule_id == rule_id)
            count_stmt = count_stmt.where(NormalizedEvent.rule_id == rule_id)
        if agent_id:
            stmt = stmt.where(NormalizedEvent.agent_id == agent_id)
            count_stmt = count_stmt.where(NormalizedEvent.agent_id == agent_id)

        total_res = await db.execute(count_stmt)
        total = total_res.scalar() or 0

        stmt = stmt.order_by(NormalizedEvent.event_timestamp.desc()).limit(limit).offset(offset)
        result = await db.execute(stmt)
        rows = result.all()

        events: list[NormalizedEventSchema] = []
        for event, raw_json in rows:
            events.append(
                NormalizedEventSchema(
                    event_id=event.id,
                    raw_alert_id=event.raw_alert_id,
                    wazuh_index_id=event.wazuh_index_id or "",
                    wazuh_index=event.wazuh_index or "",
                    normalization_version=event.normalization_version or "2.0.0",
                    normalized_at=event.created_at,
                    event_timestamp=event.event_timestamp,
                    ingestion_timestamp=event.created_at,
                    source_type=event.source_type,
                    decoder_name=event.decoder_name,
                    event_category=event.event_category or "system",
                    event_type=event.event_type,
                    severity=event.severity,
                    severity_label=_map_severity_label(event.severity),
                    rule_id=event.rule_id or "",
                    rule_description=event.rule_description or "",
                    rule_groups=[],
                    agent_id=event.agent_id,
                    agent_name=event.agent_name,
                    hostname=event.hostname,
                    src_ip=event.src_ip,
                    dst_ip=event.dst_ip,
                    src_port=event.src_port,
                    dst_port=event.dst_port,
                    network_protocol=event.network_protocol,
                    user=event.user,
                    auth_action=event.auth_action,
                    auth_result=event.auth_result,
                    domain=event.domain,
                    url=event.url,
                    process_name=event.process_name,
                    process_pid=event.process_pid,
                    process_command_line=event.process_command_line,
                    file_path=event.file_path,
                    file_hash_md5=event.file_hash_md5,
                    file_hash_sha256=event.file_hash_sha256,
                    mitre_technique_ids=event.mitre_technique_ids or [],
                    mitre_tactic_ids=event.mitre_tactic_ids or [],
                    compliance_frameworks={},
                    extra_fields=event.extra_fields or {},
                    raw_payload=raw_json or {},
                )
            )

        return NormalizedEventListResponse(
            total=total,
            count=len(events),
            limit=limit,
            offset=offset,
            events=events,
        )
    except Exception as exc:
        log.error("get_normalized_events_error", error=str(exc))
        raise HTTPException(
            status_code=500,
            detail=f"Failed to retrieve normalized events: {exc}",
        ) from exc


# ---------------------------------------------------------------------------
# Phase 3 — Correlation & Incident Routes
# ---------------------------------------------------------------------------


def _serialize_incident(inc: Incident) -> IncidentResponse:
    return IncidentResponse(
        id=inc.id,
        title=inc.title,
        description=inc.description,
        status=inc.status,
        severity=inc.severity,
        confidence=inc.confidence,
        first_seen=inc.first_seen,
        last_seen=inc.last_seen,
        alert_count=inc.alert_count,
        dedup_key=inc.dedup_key,
        correlation_rule_id=inc.correlation_rule_id,
        entity_context=inc.entity_context,
        mitre_techniques=inc.mitre_techniques,
        mitre_tactics=inc.mitre_tactics,
        created_at=inc.created_at,
        updated_at=inc.updated_at,
    )


def _serialize_incident_event(evt: IncidentEvent) -> IncidentEventItem:
    return IncidentEventItem(
        id=evt.id,
        incident_id=evt.incident_id,
        normalized_event_id=evt.normalized_event_id,
        correlation_rule_id=evt.correlation_rule_id,
        match_role=evt.match_role,
        confidence=evt.confidence,
        added_at=evt.added_at,
    )


@app.post(
    "/correlation/evaluate",
    tags=["Correlation"],
    summary="Evaluate a normalized event for correlation",
    response_model=EvaluateEventResponse,
)
async def evaluate_event(
    body: EvaluateEventRequest,
    db: AsyncSession = Depends(get_db),
    service: CorrelationService = Depends(get_correlation_service),
) -> EvaluateEventResponse:
    """
    Ingests a NormalizedEvent into the sliding-window correlation engine.
    Returns any Incidents created or aggregated by rule matches.
    """
    stmt = select(NormalizedEvent).where(NormalizedEvent.id == body.event_id)
    result = await db.execute(stmt)
    event = result.scalar_one_or_none()
    if not event:
        raise HTTPException(status_code=404, detail=f"NormalizedEvent {body.event_id} not found")

    incidents = await service.process_normalized_event(db, event)
    serialized_incidents = [_serialize_incident(inc) for inc in incidents]
    await db.commit()

    return EvaluateEventResponse(
        evaluated=True,
        event_id=body.event_id,
        matches_count=len(incidents),
        incidents=serialized_incidents,
    )


@app.get(
    "/incidents",
    tags=["Incidents"],
    summary="List correlated security incidents",
    response_model=IncidentListResponse,
)
async def list_incidents(
    status: IncidentStatus | None = Query(None, description="Filter by status"),
    severity: IncidentSeverity | None = Query(None, description="Filter by severity"),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    db: AsyncSession = Depends(get_db),
) -> IncidentListResponse:
    """List correlated security incidents with filtering and pagination."""
    stmt = select(Incident)
    count_stmt = select(func.count(Incident.id))
    if status:
        stmt = stmt.where(Incident.status == status)
        count_stmt = count_stmt.where(Incident.status == status)
    if severity:
        stmt = stmt.where(Incident.severity == severity)
        count_stmt = count_stmt.where(Incident.severity == severity)

    total_res = await db.execute(count_stmt)
    total = total_res.scalar() or 0

    stmt = stmt.order_by(Incident.last_seen.desc()).limit(limit).offset(offset)
    result = await db.execute(stmt)
    incidents = result.scalars().all()

    return IncidentListResponse(
        items=[_serialize_incident(inc) for inc in incidents],
        total=total,
        limit=limit,
        offset=offset,
    )


@app.get(
    "/incidents/{id}",
    tags=["Incidents"],
    summary="Get incident details by ID",
    response_model=IncidentDetailResponse,
)
async def get_incident(
    id: UUID,
    db: AsyncSession = Depends(get_db),
) -> IncidentDetailResponse:
    """Retrieve full incident details including member evidence events."""
    stmt = select(Incident).where(Incident.id == id)
    result = await db.execute(stmt)
    inc = result.scalar_one_or_none()
    if not inc:
        raise HTTPException(status_code=404, detail=f"Incident {id} not found")

    events_stmt = (
        select(IncidentEvent)
        .where(IncidentEvent.incident_id == id)
        .order_by(IncidentEvent.added_at.asc())
    )
    events_res = await db.execute(events_stmt)
    events = events_res.scalars().all()

    base_resp = _serialize_incident(inc)
    return IncidentDetailResponse(
        **base_resp.model_dump(),
        events=[_serialize_incident_event(e) for e in events],
    )


@app.get(
    "/incidents/{id}/events",
    tags=["Incidents"],
    summary="Get events belonging to an incident",
    response_model=IncidentEventsListResponse,
)
async def get_incident_events(
    id: UUID,
    db: AsyncSession = Depends(get_db),
) -> IncidentEventsListResponse:
    """Retrieve all normalized events associated with an incident."""
    stmt = select(Incident.id).where(Incident.id == id)
    inc_id = (await db.execute(stmt)).scalar_one_or_none()
    if not inc_id:
        raise HTTPException(status_code=404, detail=f"Incident {id} not found")

    events_stmt = (
        select(IncidentEvent)
        .where(IncidentEvent.incident_id == id)
        .order_by(IncidentEvent.added_at.asc())
    )
    events = (await db.execute(events_stmt)).scalars().all()
    return IncidentEventsListResponse(
        items=[_serialize_incident_event(e) for e in events],
        total=len(events),
    )


@app.get(
    "/correlation/rules",
    tags=["Correlation"],
    summary="List correlation rules",
    response_model=CorrelationRulesListResponse,
)
async def list_correlation_rules(
    db: AsyncSession = Depends(get_db),
) -> CorrelationRulesListResponse:
    """List all correlation rules configured in the platform."""
    # Ensure default rules exist in DB
    for default_rule in _rule_registry.get_active_rules():
        stmt = pg_insert(CorrelationRule).values(
            id=default_rule.id,
            name=default_rule.name,
            description=default_rule.description,
            rule_type=default_rule.rule_type,
            severity=default_rule.severity.value,
            base_confidence=default_rule.base_confidence,
            time_window_seconds=default_rule.time_window_seconds,
            min_event_count=default_rule.min_event_count,
            entity_field=default_rule.entity_field,
            conditions=default_rule.conditions,
            is_active=default_rule.is_active,
            priority=default_rule.priority,
            version=default_rule.version,
            mitre_technique_id=default_rule.mitre_technique_id,
            mitre_tactic_id=default_rule.mitre_tactic_id,
        ).on_conflict_do_nothing()
        await db.execute(stmt)
    await db.commit()

    stmt = select(CorrelationRule).order_by(CorrelationRule.priority.asc(), CorrelationRule.id.asc())
    db_rules = (await db.execute(stmt)).scalars().all()

    items: list[CorrelationRuleResponse] = []
    for r in db_rules:
        items.append(
            CorrelationRuleResponse(
                id=r.id,
                name=r.name,
                description=r.description,
                rule_type=r.rule_type,
                severity=r.severity,
                base_confidence=r.base_confidence,
                time_window_seconds=r.time_window_seconds,
                min_event_count=r.min_event_count,
                entity_field=r.entity_field,
                conditions=r.conditions,
                is_active=r.is_active,
                priority=r.priority,
                version=r.version,
                mitre_technique_id=r.mitre_technique_id,
                mitre_tactic_id=r.mitre_tactic_id,
                created_at=r.created_at,
                updated_at=r.updated_at,
            )
        )
    return CorrelationRulesListResponse(items=items, total=len(items))


@app.post(
    "/correlation/rules",
    tags=["Correlation"],
    summary="Create and register a new correlation rule",
    response_model=CorrelationRuleResponse,
)
async def create_correlation_rule(
    body: CorrelationRuleCreateRequest,
    db: AsyncSession = Depends(get_db),
) -> CorrelationRuleResponse:
    """Create a new correlation rule, persist to database, and register into engine."""
    rule_def = CorrelationRuleDefinition(
        name=body.name,
        description=body.description,
        rule_type=body.rule_type,
        severity=IncidentSeverity(body.severity) if hasattr(IncidentSeverity, body.severity.upper()) else IncidentSeverity.MEDIUM,
        base_confidence=body.base_confidence,
        time_window_seconds=body.time_window_seconds,
        min_event_count=body.min_event_count,
        entity_field=body.entity_field,
        conditions=body.conditions,
        is_active=body.is_active,
        priority=body.priority,
        mitre_technique_id=body.mitre_technique_id,
        mitre_tactic_id=body.mitre_tactic_id,
    )

    db_rule = CorrelationRule(
        id=rule_def.id,
        name=rule_def.name,
        description=rule_def.description,
        rule_type=rule_def.rule_type,
        severity=rule_def.severity.value,
        base_confidence=rule_def.base_confidence,
        time_window_seconds=rule_def.time_window_seconds,
        min_event_count=rule_def.min_event_count,
        entity_field=rule_def.entity_field,
        conditions=rule_def.conditions,
        is_active=rule_def.is_active,
        priority=rule_def.priority,
        version=rule_def.version,
        mitre_technique_id=rule_def.mitre_technique_id,
        mitre_tactic_id=rule_def.mitre_tactic_id,
    )
    db.add(db_rule)
    await db.commit()
    await db.refresh(db_rule)

    _rule_registry.register_rule(rule_def)

    return CorrelationRuleResponse(
        id=db_rule.id,
        name=db_rule.name,
        description=db_rule.description,
        rule_type=db_rule.rule_type,
        severity=db_rule.severity,
        base_confidence=db_rule.base_confidence,
        time_window_seconds=db_rule.time_window_seconds,
        min_event_count=db_rule.min_event_count,
        entity_field=db_rule.entity_field,
        conditions=db_rule.conditions,
        is_active=db_rule.is_active,
        priority=db_rule.priority,
        version=db_rule.version,
        mitre_technique_id=db_rule.mitre_technique_id,
        mitre_tactic_id=db_rule.mitre_tactic_id,
        created_at=db_rule.created_at,
        updated_at=db_rule.updated_at,
    )