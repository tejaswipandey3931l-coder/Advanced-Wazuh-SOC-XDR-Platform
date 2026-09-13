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
from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.responses import JSONResponse

from .config import get_settings
from .exceptions import IntegrationError
from .logging_config import configure_logging
from .schemas.wazuh import (
    AlertListResponse,
    WazuhApiInfo,
    WazuhManagerInfo,
    WazuhManagerStatus,
)
from .wazuh_client import WazuhClient, WazuhIndexerClient

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