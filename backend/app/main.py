"""
Advanced Wazuh SOC/XDR — FastAPI application entry point.

Startup order:
  1. Logging is configured (structlog).
  2. Application state is validated (settings loaded).
  3. Routes are registered.
  4. Application is ready to serve requests.
"""

from __future__ import annotations

from contextlib import asynccontextmanager
from typing import Any

import structlog
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse

from .config import get_settings
from .logging_config import configure_logging
from .wazuh_client import WazuhClient

# ---------------------------------------------------------------------------
# Bootstrap — configure logging before anything else so that all subsequent
# imports and startup messages are captured with the correct format.
# ---------------------------------------------------------------------------
_settings = get_settings()
configure_logging(debug=_settings.app_debug)

log = structlog.get_logger(__name__)


# ---------------------------------------------------------------------------
# Lifespan context manager (FastAPI 0.93+ pattern).
# Runs startup logic before the first request and teardown on shutdown.
# ---------------------------------------------------------------------------
@asynccontextmanager
async def lifespan(app: FastAPI):
    log.info(
        "application_startup",
        name=_settings.app_name,
        version=_settings.app_version,
        debug=_settings.app_debug,
        wazuh_api_url=_settings.wazuh_api_url,
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
# Routes
# ---------------------------------------------------------------------------

@app.get(
    "/health",
    tags=["System"],
    summary="Health check",
    response_description="Service is healthy",
)
async def health() -> dict[str, Any]:
    """Return a simple liveness probe response.

    Does not check downstream dependencies (Wazuh, DB, Redis).
    Use dedicated readiness endpoints for deep health checks.
    """
    log.debug("health_check_called")
    return {
        "status": "ok",
        "service": "advanced-wazuh-soc",
        "version": _settings.app_version,
    }


@app.get(
    "/wazuh/info",
    tags=["Wazuh"],
    summary="Wazuh API information",
    response_description="Wazuh manager API metadata",
)
async def wazuh_info() -> dict[str, Any]:
    """Return Wazuh API version and metadata.

    Authenticates against the Wazuh REST API and returns the top-level
    info object.  Used to verify Wazuh connectivity.
    """
    log.info("wazuh_info_requested")
    try:
        client = WazuhClient()
        result = await client.get_api_info()
        log.info("wazuh_info_success")
        return result
    except Exception as exc:
        log.error("wazuh_info_failed", error=str(exc))
        raise HTTPException(
            status_code=502,
            detail=f"Wazuh API connection failed: {exc}",
        )