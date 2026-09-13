"""
Endpoint tests for Wazuh API routes (/wazuh/info, /wazuh/manager, /wazuh/status, /wazuh/alerts).

Tests use the async HTTPX test client bound to FastAPI ASGI (no network sockets).
WazuhClient and WazuhIndexerClient methods are mocked to test response schemas,
parameter validations, and error mappings.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, patch

import pytest
from httpx import AsyncClient

from backend.app.exceptions import (
    OpenSearchAuthenticationError,
    OpenSearchConnectionError,
    OpenSearchIndexNotFoundError,
    OpenSearchQueryError,
    OpenSearchTimeoutError,
    WazuhAuthenticationError,
    WazuhConnectionError,
    WazuhResponseError,
    WazuhTimeoutError,
)
from backend.app.schemas.wazuh import (
    AlertListResponse,
    RawAlertItem,
    WazuhApiInfo,
    WazuhManagerInfo,
    WazuhManagerStatus,
)


# ── /wazuh/info Tests ─────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_get_wazuh_info_success(client: AsyncClient):
    """Verify /wazuh/info returns 200 with WazuhApiInfo schema."""
    expected_info = WazuhApiInfo(
        title="Wazuh API REST",
        api_version="4.14.7",
        revision="401407",
        hostname="kali-host",
        timestamp="2026-09-13T12:00:00Z",
    )

    with patch("backend.app.main.WazuhClient.get_api_info", new_callable=AsyncMock) as mock_info:
        mock_info.return_value = expected_info

        resp = await client.get("/wazuh/info")
        assert resp.status_code == 200
        data = resp.json()
        assert data["title"] == "Wazuh API REST"
        assert data["api_version"] == "4.14.7"
        assert data["hostname"] == "kali-host"


@pytest.mark.asyncio
async def test_get_wazuh_info_auth_failure(client: AsyncClient):
    """Verify /wazuh/info returns 401 when Wazuh authentication fails."""
    with patch("backend.app.main.WazuhClient.get_api_info", new_callable=AsyncMock) as mock_info:
        mock_info.side_effect = WazuhAuthenticationError("Invalid Wazuh API credentials")

        resp = await client.get("/wazuh/info")
        assert resp.status_code == 401
        data = resp.json()
        assert data["detail"] == "Invalid Wazuh API credentials"
        assert data["error_type"] == "WazuhAuthenticationError"


@pytest.mark.asyncio
async def test_get_wazuh_info_connection_failure(client: AsyncClient):
    """Verify /wazuh/info returns 503 when Wazuh API service is unreachable."""
    with patch("backend.app.main.WazuhClient.get_api_info", new_callable=AsyncMock) as mock_info:
        mock_info.side_effect = WazuhConnectionError("Wazuh API service unavailable")

        resp = await client.get("/wazuh/info")
        assert resp.status_code == 503
        data = resp.json()
        assert data["detail"] == "Wazuh API service unavailable"


# ── /wazuh/manager Tests ──────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_get_wazuh_manager_success(client: AsyncClient):
    """Verify /wazuh/manager returns 200 with WazuhManagerInfo schema."""
    expected_mgr = WazuhManagerInfo(
        version="v4.14.7",
        type="server",
        path="/var/ossec",
        uuid="uuid-999-aaa",
        tz_offset="+0000",
        tz_name="UTC",
    )

    with patch("backend.app.main.WazuhClient.get_manager_info", new_callable=AsyncMock) as mock_mgr:
        mock_mgr.return_value = expected_mgr

        resp = await client.get("/wazuh/manager")
        assert resp.status_code == 200
        data = resp.json()
        assert data["version"] == "v4.14.7"
        assert data["path"] == "/var/ossec"
        assert data["uuid"] == "uuid-999-aaa"


@pytest.mark.asyncio
async def test_get_wazuh_manager_timeout(client: AsyncClient):
    """Verify /wazuh/manager returns 504 on timeout."""
    with patch("backend.app.main.WazuhClient.get_manager_info", new_callable=AsyncMock) as mock_mgr:
        mock_mgr.side_effect = WazuhTimeoutError("Wazuh API request timed out")

        resp = await client.get("/wazuh/manager")
        assert resp.status_code == 504
        data = resp.json()
        assert data["detail"] == "Wazuh API request timed out"


# ── /wazuh/status Tests ───────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_get_wazuh_status_success(client: AsyncClient):
    """Verify /wazuh/status returns 200 with WazuhManagerStatus schema."""
    expected_status = WazuhManagerStatus(
        daemons={
            "wazuh-analysisd": "running",
            "wazuh-execd": "running",
            "wazuh-modulesd": "running",
        }
    )

    with patch("backend.app.main.WazuhClient.get_manager_status", new_callable=AsyncMock) as mock_status:
        mock_status.return_value = expected_status

        resp = await client.get("/wazuh/status")
        assert resp.status_code == 200
        data = resp.json()
        assert data["daemons"]["wazuh-analysisd"] == "running"
        assert data["daemons"]["wazuh-execd"] == "running"


# ── /wazuh/alerts Tests ───────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_get_wazuh_alerts_with_hits(client: AsyncClient):
    """Verify /wazuh/alerts returns 200 with paginated raw alerts and intact raw dictionary."""
    expected_response = AlertListResponse(
        total=1,
        count=1,
        limit=20,
        offset=0,
        alerts=[
            RawAlertItem(
                id="alert-doc-100",
                index="wazuh-alerts-4.x-2026.09.13",
                timestamp="2026-09-13T11:00:00Z",
                rule_id="5715",
                rule_level=10,
                rule_description="SSHD authentication failure",
                agent_id="001",
                agent_name="kali",
                raw={"original": "payload", "rule": {"id": "5715"}},
            )
        ],
    )

    with patch("backend.app.main.WazuhIndexerClient.get_alerts", new_callable=AsyncMock) as mock_alerts:
        mock_alerts.return_value = expected_response

        resp = await client.get("/wazuh/alerts?limit=20&offset=0&min_level=7&rule_id=5715")
        assert resp.status_code == 200
        data = resp.json()
        assert data["total"] == 1
        assert data["count"] == 1
        assert len(data["alerts"]) == 1
        assert data["alerts"][0]["id"] == "alert-doc-100"
        assert data["alerts"][0]["rule_id"] == "5715"
        assert data["alerts"][0]["raw"]["original"] == "payload"


@pytest.mark.asyncio
async def test_get_wazuh_alerts_zero_results_is_valid_success(client: AsyncClient):
    """Verify that an empty alert query returning 0 alerts returns 200 OK (Amendment 3)."""
    expected_empty = AlertListResponse(
        total=0,
        count=0,
        limit=20,
        offset=0,
        alerts=[],
    )

    with patch("backend.app.main.WazuhIndexerClient.get_alerts", new_callable=AsyncMock) as mock_alerts:
        mock_alerts.return_value = expected_empty

        resp = await client.get("/wazuh/alerts?limit=20&offset=0&min_level=14")
        assert resp.status_code == 200
        data = resp.json()
        assert data["total"] == 0
        assert data["count"] == 0
        assert data["alerts"] == []


@pytest.mark.asyncio
async def test_get_wazuh_alerts_validation_errors(client: AsyncClient):
    """Verify query parameter boundary validations (limit, offset, min_level)."""
    # limit < 1
    resp = await client.get("/wazuh/alerts?limit=0")
    assert resp.status_code == 422

    # limit > 500
    resp = await client.get("/wazuh/alerts?limit=501")
    assert resp.status_code == 422

    # offset < 0
    resp = await client.get("/wazuh/alerts?offset=-1")
    assert resp.status_code == 422

    # min_level < 0
    resp = await client.get("/wazuh/alerts?min_level=-1")
    assert resp.status_code == 422

    # min_level > 16
    resp = await client.get("/wazuh/alerts?min_level=17")
    assert resp.status_code == 422

    # start_time invalid datetime
    resp = await client.get("/wazuh/alerts?start_time=not-a-valid-datetime")
    assert resp.status_code == 422


@pytest.mark.asyncio
async def test_get_wazuh_alerts_opensearch_connection_error(client: AsyncClient):
    """Verify /wazuh/alerts returns 503 when OpenSearch is unreachable."""
    with patch("backend.app.main.WazuhIndexerClient.get_alerts", new_callable=AsyncMock) as mock_alerts:
        mock_alerts.side_effect = OpenSearchConnectionError("OpenSearch service unreachable")

        resp = await client.get("/wazuh/alerts")
        assert resp.status_code == 503
        data = resp.json()
        assert data["detail"] == "OpenSearch service unreachable"
        assert data["error_type"] == "OpenSearchConnectionError"


@pytest.mark.asyncio
async def test_get_wazuh_alerts_opensearch_timeout_error(client: AsyncClient):
    """Verify /wazuh/alerts returns 504 when OpenSearch query times out."""
    with patch("backend.app.main.WazuhIndexerClient.get_alerts", new_callable=AsyncMock) as mock_alerts:
        mock_alerts.side_effect = OpenSearchTimeoutError("OpenSearch query timed out")

        resp = await client.get("/wazuh/alerts")
        assert resp.status_code == 504
        data = resp.json()
        assert data["detail"] == "OpenSearch query timed out"


@pytest.mark.asyncio
async def test_get_wazuh_alerts_opensearch_auth_error(client: AsyncClient):
    """Verify /wazuh/alerts returns 401 on OpenSearch authentication error."""
    with patch("backend.app.main.WazuhIndexerClient.get_alerts", new_callable=AsyncMock) as mock_alerts:
        mock_alerts.side_effect = OpenSearchAuthenticationError("OpenSearch authentication failed")

        resp = await client.get("/wazuh/alerts")
        assert resp.status_code == 401
        data = resp.json()
        assert data["detail"] == "OpenSearch authentication failed"


@pytest.mark.asyncio
async def test_get_wazuh_alerts_opensearch_index_not_found_error(client: AsyncClient):
    """Verify /wazuh/alerts returns 404 when OpenSearch index or pattern does not exist."""
    with patch("backend.app.main.WazuhIndexerClient.get_alerts", new_callable=AsyncMock) as mock_alerts:
        mock_alerts.side_effect = OpenSearchIndexNotFoundError(
            "OpenSearch index or resource not found: /missing-index/_search"
        )

        resp = await client.get("/wazuh/alerts")
        assert resp.status_code == 404
        data = resp.json()
        assert data["detail"] == "OpenSearch index or resource not found: /missing-index/_search"
        assert data["error_type"] == "OpenSearchIndexNotFoundError"

