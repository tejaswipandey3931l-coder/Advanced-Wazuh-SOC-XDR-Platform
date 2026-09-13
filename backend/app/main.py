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
from datetime import datetime
from typing import Any

import structlog
from fastapi import Depends, FastAPI, HTTPException, Query, Request
from fastapi.responses import JSONResponse
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from .config import get_settings
from .database import get_db
from .exceptions import IntegrationError
from .logging_config import configure_logging
from .models.normalized_event import NormalizedEvent
from .models.raw_alert import RawAlert
from .schemas.wazuh import (
    AlertListResponse,
    RawAlertItem,
    WazuhApiInfo,
    WazuhManagerInfo,
    WazuhManagerStatus,
)
from .wazuh_client import WazuhClient, WazuhIndexerClient
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
    )
    yield
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