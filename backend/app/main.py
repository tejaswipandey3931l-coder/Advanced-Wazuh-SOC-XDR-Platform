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

import time
from .models.audit_log import AuditLog
from .models.threat_intel_result import CTISource, IOCType, ThreatIntelResult
from .schemas.threat_intel import (
    CacheInvalidateRequest,
    CacheInvalidateResponse,
    EnrichedObservableSchema,
    EnrichmentBatchResponse,
    EnrichmentRequest,
    EventEnrichmentResponse,
    IncidentEnrichmentResponse,
    ProviderStatusListResponse,
    ThreatIntelResultItem,
    ThreatIntelResultListResponse,
)
from .schemas.risk import (
    RiskHistoryResponse,
    RiskRecalculateRequest,
    RiskScoreResponse,
    RiskSimulateRequest,
    RiskSimulateResponse,
)
from threat_intel.normalizer import normalize_observable
from threat_intel.service import ThreatIntelService

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


# ── Threat Intelligence Service Setup ─────────────────────────────────────────
_threat_intel_service = ThreatIntelService()


def get_threat_intel_service() -> ThreatIntelService:
    return _threat_intel_service


# ── Dynamic Risk Engine Setup ────────────────────────────────────────────────
from risk_engine.service import RiskService
from risk_engine.calculator import calculate_risk_v1
from risk_engine.explainer import build_explanation
from risk_engine.models import FactorInputs

_risk_service = RiskService()


def get_risk_service() -> RiskService:
    return _risk_service


# ── Threat Intelligence Admin Auth Hook & Rate Limiting ───────────────────────
def get_admin_auth_hook(request: Request) -> bool:
    """
    Administrative authorization dependency hook for Phase 4.
    Protects cache invalidation and forced cache refresh.
    Defaults to rejecting unauthorized access with HTTP 403 in production.
    Accepts FastAPI dependency overrides in tests.
    """
    # Check FastAPI dependency overrides (for testing)
    override = app.dependency_overrides.get(get_admin_auth_hook)
    if override:
        try:
            return override(request)
        except TypeError:
            return override()

    cfg = get_settings()
    configured_token = cfg.ti_admin_token

    if not configured_token:
        log.warning("admin_auth_rejected_unconfigured_token", path=request.url.path)
        raise HTTPException(
            status_code=403,
            detail="Forbidden: Administrative operations are disabled because ti_admin_token is unconfigured",
        )

    provided_token = request.headers.get("X-SOC-Admin-Token")
    if not provided_token:
        auth_header = request.headers.get("Authorization", "")
        if auth_header.startswith("Bearer "):
            provided_token = auth_header[7:].strip()

    if not provided_token or provided_token != configured_token:
        log.warning("admin_auth_rejected_invalid_token", path=request.url.path)
        raise HTTPException(
            status_code=403,
            detail="Forbidden: Invalid or missing administrative token",
        )

    return True


_force_refresh_timestamps: dict[str, float] = {}


def check_force_refresh_rate_limit(canonical_value: str) -> None:
    """Enforces max 1 force-refresh per observable per 60 seconds."""
    now = time.time()
    last_time = _force_refresh_timestamps.get(canonical_value)
    if last_time and (now - last_time) < 60.0:
        retry_after = int(60.0 - (now - last_time))
        raise HTTPException(
            status_code=429,
            detail=f"Rate limit exceeded: Force refresh for '{canonical_value}' is limited to once per 60s. Retry after {retry_after}s.",
            headers={"Retry-After": str(retry_after)},
        )
    _force_refresh_timestamps[canonical_value] = now


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
    await _threat_intel_service.close()
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
        evidence_version=inc.evidence_version,
        risk_score=inc.risk_score,
        risk_priority_band=inc.risk_priority_band,
        current_risk_score_id=inc.current_risk_score_id,
        risk_evidence_version=inc.risk_evidence_version,
        risk_evidence_as_of=inc.risk_evidence_as_of,
        risk_evaluation_as_of=inc.risk_evaluation_as_of,
        risk_calculated_at=inc.risk_calculated_at,
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


# ---------------------------------------------------------------------------
# Phase 4: Threat Intelligence Enrichment Endpoints
# ---------------------------------------------------------------------------
@app.post(
    "/threat-intel/enrich",
    response_model=EnrichmentBatchResponse,
    status_code=200,
    tags=["Threat Intelligence"],
)
async def enrich_observables(
    body: EnrichmentRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
) -> EnrichmentBatchResponse:
    """
    Ad-hoc observable enrichment across configured CTI providers.
    Supports up to 25 observables per request.
    Bypassing cache (force_refresh=True) requires administrative authorization.
    """
    if len(body.observables) > 25:
        raise HTTPException(
            status_code=400,
            detail="Batch limit exceeded: Maximum 25 observables permitted per enrichment request",
        )

    # Force refresh requires admin auth and rate limit check
    if body.force_refresh:
        get_admin_auth_hook(request)

    normalized_observables = []
    for item in body.observables:
        raw_val = item.ioc_value.strip()
        ioc_t = IOCType(item.ioc_type.lower()) if item.ioc_type else None
        norm = normalize_observable(raw_val, ioc_type=ioc_t)
        if not norm:
            raise HTTPException(
                status_code=422,
                detail=f"Malformed or invalid observable: '{raw_val}'",
            )
        if body.force_refresh:
            check_force_refresh_rate_limit(norm.canonical_value)
        normalized_observables.append(norm)

    enriched = await _threat_intel_service.enrich_observables(
        observables=normalized_observables,
        requested_providers=body.providers,
        force_refresh=body.force_refresh,
        db=db,
    )
    await db.commit()

    # Audit log
    audit = AuditLog(
        actor="api_client",
        action="ti_manual_enrichment",
        resource_type="observable_batch",
        details={
            "count": len(normalized_observables),
            "providers": body.providers,
            "force_refresh": body.force_refresh,
        },
        ip_address=request.client.host if request.client else None,
    )
    db.add(audit)
    await db.commit()

    return EnrichmentBatchResponse(
        total=len(enriched),
        results=[EnrichedObservableSchema.from_domain(e) for e in enriched],
    )


@app.post(
    "/threat-intel/enrich/event/{event_id}",
    response_model=EventEnrichmentResponse,
    status_code=200,
    tags=["Threat Intelligence"],
)
async def enrich_event_endpoint(
    event_id: UUID,
    request: Request,
    providers: list[str] | None = Query(default=None),
    force_refresh: bool = Query(default=False),
    db: AsyncSession = Depends(get_db),
) -> EventEnrichmentResponse:
    """Extracts, canonicalizes, and enriches all observables from a NormalizedEvent."""
    if force_refresh:
        get_admin_auth_hook(request)

    try:
        enriched = await _threat_intel_service.enrich_event(
            event_id=event_id,
            db=db,
            requested_providers=providers,
            force_refresh=force_refresh,
        )
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc))

    await db.commit()

    # Audit log
    audit = AuditLog(
        actor="system",
        action="ti_event_enrichment",
        resource_type="normalized_event",
        resource_id=str(event_id),
        details={"observables_count": len(enriched), "providers": providers},
        ip_address=request.client.host if request.client else None,
    )
    db.add(audit)
    await db.commit()

    return EventEnrichmentResponse(
        event_id=event_id,
        total_observables=len(enriched),
        results=[EnrichedObservableSchema.from_domain(e) for e in enriched],
    )


@app.post(
    "/threat-intel/enrich/incident/{incident_id}",
    response_model=IncidentEnrichmentResponse,
    status_code=200,
    tags=["Threat Intelligence"],
)
async def enrich_incident_endpoint(
    incident_id: UUID,
    request: Request,
    providers: list[str] | None = Query(default=None),
    force_refresh: bool = Query(default=False),
    db: AsyncSession = Depends(get_db),
) -> IncidentEnrichmentResponse:
    """Extracts, canonicalizes, and enriches all distinct observables from an Incident and member events."""
    if force_refresh:
        get_admin_auth_hook(request)

    try:
        enriched = await _threat_intel_service.enrich_incident(
            incident_id=incident_id,
            db=db,
            requested_providers=providers,
            force_refresh=force_refresh,
        )
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc))

    await db.commit()

    # Audit log
    audit = AuditLog(
        actor="system",
        action="ti_incident_enrichment",
        resource_type="incident",
        resource_id=str(incident_id),
        details={"observables_count": len(enriched), "providers": providers},
        ip_address=request.client.host if request.client else None,
    )
    db.add(audit)
    await db.commit()

    return IncidentEnrichmentResponse(
        incident_id=incident_id,
        total_observables=len(enriched),
        results=[EnrichedObservableSchema.from_domain(e) for e in enriched],
    )


@app.get(
    "/threat-intel/results",
    response_model=ThreatIntelResultListResponse,
    status_code=200,
    tags=["Threat Intelligence"],
)
async def get_threat_intel_results(
    verdict: str | None = Query(default=None),
    ioc_type: str | None = Query(default=None),
    source: str | None = Query(default=None),
    ioc_value: str | None = Query(default=None),
    limit: int = Query(default=50, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    db: AsyncSession = Depends(get_db),
) -> ThreatIntelResultListResponse:
    """Queries historical threat intelligence lookup results with filtering and pagination."""
    query = select(ThreatIntelResult)
    count_query = select(func.count(ThreatIntelResult.id))

    if verdict:
        query = query.where(ThreatIntelResult.verdict == verdict.lower())
        count_query = count_query.where(ThreatIntelResult.verdict == verdict.lower())
    if ioc_type:
        try:
            it = IOCType(ioc_type.lower())
            query = query.where(ThreatIntelResult.ioc_type == it)
            count_query = count_query.where(ThreatIntelResult.ioc_type == it)
        except ValueError:
            return ThreatIntelResultListResponse(total=0, limit=limit, offset=offset, results=[])
    if source:
        try:
            cs = CTISource(source.lower())
            query = query.where(ThreatIntelResult.source == cs)
            count_query = count_query.where(ThreatIntelResult.source == cs)
        except ValueError:
            return ThreatIntelResultListResponse(total=0, limit=limit, offset=offset, results=[])
    if ioc_value:
        v_low = ioc_value.lower()
        query = query.where(ThreatIntelResult.ioc_value == v_low)
        count_query = count_query.where(ThreatIntelResult.ioc_value == v_low)

    total_res = await db.execute(count_query)
    total = total_res.scalar() or 0

    query = query.order_by(ThreatIntelResult.queried_at.desc()).offset(offset).limit(limit)
    rows_res = await db.execute(query)
    rows = rows_res.scalars().all()

    items = [
        ThreatIntelResultItem(
            id=r.id,
            normalized_event_id=r.normalized_event_id,
            incident_id=r.incident_id,
            ioc_type=r.ioc_type.value,
            ioc_value=r.ioc_value,
            source=r.source.value,
            matched=r.matched,
            verdict=r.verdict,
            severity=r.severity,
            confidence=r.confidence,
            provider_confidence=r.provider_confidence,
            derived_heuristic_confidence=r.derived_heuristic_confidence,
            threat_type=r.threat_type,
            context=r.context,
            raw_response_text=r.raw_response_text,
            source_reference=r.source_reference,
            queried_at=r.queried_at,
            cache_expires_at=r.cache_expires_at,
            created_at=r.created_at,
        )
        for r in rows
    ]

    return ThreatIntelResultListResponse(
        total=total,
        limit=limit,
        offset=offset,
        results=items,
    )


@app.get(
    "/threat-intel/providers",
    response_model=ProviderStatusListResponse,
    status_code=200,
    tags=["Threat Intelligence"],
)
async def get_threat_intel_providers() -> ProviderStatusListResponse:
    """Returns operational status, configuration health, and cache metrics for CTI providers."""
    health = await _threat_intel_service.check_health()
    return ProviderStatusListResponse(
        status=health.get("status", "unknown"),
        cache=health.get("cache", {}),
        providers=health.get("providers", []),
    )


@app.post(
    "/threat-intel/cache/invalidate",
    response_model=CacheInvalidateResponse,
    status_code=200,
    tags=["Threat Intelligence"],
)
async def invalidate_threat_intel_cache(
    body: CacheInvalidateRequest,
    request: Request,
    admin_auth: bool = Depends(get_admin_auth_hook),
    db: AsyncSession = Depends(get_db),
) -> CacheInvalidateResponse:
    """
    Purges threat intelligence cache entries.
    Administrative endpoint protected by explicit authorization dependency hook.
    """
    obs = None
    if body.ioc_value:
        it = IOCType(body.ioc_type.lower()) if body.ioc_type else None
        obs = normalize_observable(body.ioc_value, ioc_type=it)

    deleted = await _threat_intel_service.invalidate_cache(
        provider=body.provider,
        observable=obs,
        key_pattern=body.key_pattern,
    )

    target_desc = body.key_pattern or (
        f"{body.provider}:{body.ioc_value}" if body.provider and body.ioc_value else (body.provider or "all")
    )

    # Audit log
    audit = AuditLog(
        actor="admin",
        action="ti_cache_invalidation",
        resource_type="cti_cache",
        details={"target": target_desc, "deleted_count": deleted},
        ip_address=request.client.host if request.client else None,
    )
    db.add(audit)
    await db.commit()

    return CacheInvalidateResponse(
        deleted_entries=deleted,
        target=target_desc,
        invalidated_at=datetime.now(timezone.utc),
    )


# ---------------------------------------------------------------------------
# Phase 5 — Dynamic Risk Scoring & Prioritization Routes
# ---------------------------------------------------------------------------


@app.post(
    "/incidents/{incident_id}/risk/recalculate",
    response_model=RiskScoreResponse,
    status_code=200,
    tags=["Dynamic Risk Engine"],
    summary="Recalculate dynamic risk score for an incident",
)
async def recalculate_incident_risk(
    incident_id: UUID,
    body: RiskRecalculateRequest | None = None,
    db: AsyncSession = Depends(get_db),
) -> RiskScoreResponse:
    """Manually recalculates dynamic risk score for an incident."""
    eval_as_of = body.evaluation_as_of if body else None
    result = await _risk_service.evaluate_incident(
        db=db,
        incident_id=incident_id,
        evaluation_as_of=eval_as_of,
        trigger_reason="manual_recalculate",
    )
    if not result:
        raise HTTPException(status_code=404, detail=f"Incident {incident_id} not found")

    return RiskScoreResponse.from_domain(
        result=result,
        incident_id=incident_id,
        score_id=result.risk_score_id,
        trigger_reason="manual_recalculate",
    )


@app.get(
    "/incidents/{incident_id}/risk",
    response_model=RiskScoreResponse,
    status_code=200,
    tags=["Dynamic Risk Engine"],
    summary="Get latest dynamic risk score for an incident",
)
async def get_incident_risk(
    incident_id: UUID,
    db: AsyncSession = Depends(get_db),
) -> RiskScoreResponse:
    """Retrieves current dynamic risk score for an incident."""
    stmt = select(Incident.id).where(Incident.id == incident_id)
    inc_exists = (await db.execute(stmt)).scalar_one_or_none()
    if not inc_exists:
        raise HTTPException(status_code=404, detail=f"Incident {incident_id} not found")

    result = await _risk_service.get_latest_risk(db=db, incident_id=incident_id)
    if not result:
        result = await _risk_service.evaluate_incident(
            db=db,
            incident_id=incident_id,
            trigger_reason="on_demand",
        )
    if not result:
        raise HTTPException(status_code=404, detail=f"No risk score available for incident {incident_id}")

    return RiskScoreResponse.from_domain(
        result=result,
        incident_id=incident_id,
        score_id=result.risk_score_id,
        trigger_reason="query",
    )


@app.get(
    "/incidents/{incident_id}/risk/history",
    response_model=RiskHistoryResponse,
    status_code=200,
    tags=["Dynamic Risk Engine"],
    summary="Get append-only risk score history for an incident",
)
async def get_incident_risk_history(
    incident_id: UUID,
    limit: int = Query(default=50, ge=1, le=500),
    db: AsyncSession = Depends(get_db),
) -> RiskHistoryResponse:
    """Retrieves chronological append-only risk evaluation history for an incident."""
    stmt = select(Incident.id).where(Incident.id == incident_id)
    inc_exists = (await db.execute(stmt)).scalar_one_or_none()
    if not inc_exists:
        raise HTTPException(status_code=404, detail=f"Incident {incident_id} not found")

    results = await _risk_service.get_risk_history(db=db, incident_id=incident_id, limit=limit)
    items = [
        RiskScoreResponse.from_domain(
            result=r,
            incident_id=incident_id,
            score_id=r.risk_score_id,
            trigger_reason="history",
        )
        for r in results
    ]
    return RiskHistoryResponse(
        incident_id=incident_id,
        items=items,
        total=len(items),
    )


@app.post(
    "/risk/evaluate",
    response_model=RiskSimulateResponse,
    status_code=200,
    tags=["Dynamic Risk Engine"],
    summary="Stateless risk-v1 evaluation simulation",
)
async def simulate_risk_evaluation(
    body: RiskSimulateRequest,
) -> RiskSimulateResponse:
    """Stateless risk calculation simulation for dry-run analysis and sensitivity exploration."""
    calc_result = calculate_risk_v1(body.factors)
    calc_time = datetime.now(timezone.utc)
    explanation = build_explanation(calc_result, calculated_at=calc_time)

    return RiskSimulateResponse(
        overall_score=calc_result["overall_score"],
        priority_band=calc_result["priority_band"].value,
        base_score=calc_result["base_score"],
        temporal_decay=calc_result["temporal_decay"],
        sub_scores={
            "severity": calc_result["sub_scores"].severity,
            "correlation": calc_result["sub_scores"].correlation,
            "cti": calc_result["sub_scores"].cti,
            "volume": calc_result["sub_scores"].volume,
            "mitre_coverage": calc_result["sub_scores"].mitre_coverage,
        },
        effective_weights=calc_result["effective_weights"],
        factors=calc_result["factors"],
        explanation=explanation.model_dump(mode="json"),
        clean_mitigation=calc_result["clean_mitigation"],
        evidence_version=body.factors.evidence_version,
        evidence_as_of=body.factors.evidence_as_of,
        evaluation_as_of=body.factors.evaluation_as_of,
        calculated_at=calc_time,
    )