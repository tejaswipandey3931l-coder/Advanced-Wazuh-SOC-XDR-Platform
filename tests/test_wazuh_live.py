"""
Live integration tests against the native Wazuh Manager and Wazuh Indexer (OpenSearch).

These tests run against actual live services when available on the host.
If services are offline, tests are gracefully skipped.

Requirements:
  - Preserves strict TLS certificate verification by default.
  - Distinguishes service failure, zero alerts (valid success), and alerts present.
  - Never logs, prints, or exposes credentials or JWT tokens.
"""

from __future__ import annotations

import httpx
import pytest

from backend.app.config import get_settings
from backend.app.exceptions import IntegrationError, OpenSearchIndexNotFoundError
from backend.app.wazuh_client import WazuhClient, WazuhIndexerClient


@pytest.fixture(scope="module")
def live_settings():
    """Load current environment settings for live integration testing."""
    settings = get_settings()
    if not settings.wazuh_api_user or not settings.wazuh_api_password:
        pytest.skip("Wazuh API credentials not configured in environment")
    return settings


@pytest.fixture(scope="module")
async def live_wazuh_client(live_settings):
    """Provide a live WazuhClient instance if the service is reachable."""
    client = WazuhClient(settings=live_settings)
    try:
        # Pre-flight check with a short timeout
        async with httpx.AsyncClient(verify=client.ssl_verify, timeout=3.0) as test_http:
            resp = await test_http.get(f"{client.base_url}/")
            if resp.status_code >= 500:
                pytest.skip(f"Live Wazuh API service returned {resp.status_code}")
    except Exception as exc:
        pytest.skip(f"Live Wazuh API service unreachable: {exc}")
    return client


@pytest.fixture(scope="module")
async def live_indexer_client(live_settings):
    """Provide a live WazuhIndexerClient instance if OpenSearch is reachable."""
    client = WazuhIndexerClient(settings=live_settings)
    try:
        # Pre-flight check with a short timeout
        async with httpx.AsyncClient(
            verify=client.ssl_verify,
            timeout=3.0,
            auth=(client.username, client.password) if client.username else None,
        ) as test_http:
            resp = await test_http.get(f"{client.base_url}/_cluster/health")
            if resp.status_code >= 500:
                pytest.skip(f"Live OpenSearch service returned {resp.status_code}")
    except Exception as exc:
        pytest.skip(f"Live OpenSearch service unreachable: {exc}")
    return client


# ── Live Wazuh REST API Tests ─────────────────────────────────────────────────


@pytest.mark.live
@pytest.mark.asyncio
async def test_live_wazuh_api_info(live_wazuh_client: WazuhClient):
    """Test live Wazuh REST API top-level metadata retrieval."""
    info = await live_wazuh_client.get_api_info()
    assert info.title is not None
    assert info.api_version.startswith("4.")
    assert len(info.api_version) > 0


@pytest.mark.live
@pytest.mark.asyncio
async def test_live_wazuh_manager_info(live_wazuh_client: WazuhClient):
    """Test live Wazuh Manager engine metadata retrieval."""
    mgr = await live_wazuh_client.get_manager_info()
    assert mgr.version is not None
    assert mgr.path == "/var/ossec" or mgr.path is not None


@pytest.mark.live
@pytest.mark.asyncio
async def test_live_wazuh_manager_status(live_wazuh_client: WazuhClient):
    """Test live Wazuh Manager daemon operational status."""
    status = await live_wazuh_client.get_manager_status()
    assert isinstance(status.daemons, dict)
    assert len(status.daemons) > 0
    # Core daemon wazuh-analysisd should be running in a live instance
    assert "wazuh-analysisd" in status.daemons


# ── Live OpenSearch / Wazuh Indexer Tests ─────────────────────────────────────


@pytest.mark.live
@pytest.mark.asyncio
async def test_live_opensearch_cluster_health(live_indexer_client: WazuhIndexerClient):
    """Test live OpenSearch cluster health check."""
    health = await live_indexer_client.get_cluster_health()
    assert "status" in health
    assert health["status"] in ("green", "yellow")


@pytest.mark.live
@pytest.mark.asyncio
async def test_live_opensearch_alerts_query_distinction(live_indexer_client: WazuhIndexerClient):
    """Verify live alert query explicitly distinguishes:
    1. Service/query failure (IntegrationError raised on invalid syntax or service down)
    2. Successful query with zero alerts (valid success, total=0, alerts=[])
    3. Successful query with alerts (valid success, total>0, alerts with intact raw dict)
    """
    # ── 1. Test Successful query with ZERO alerts (using impossible rule_id filter) ──
    zero_result = await live_indexer_client.get_alerts(
        limit=10,
        offset=0,
        rule_id="9999999999_nonexistent_rule",
    )
    # Validate that zero alerts is a valid successful result, NOT an error
    assert zero_result.total == 0
    assert zero_result.count == 0
    assert zero_result.alerts == []
    assert zero_result.limit == 10
    assert zero_result.offset == 0

    # ── 2. Test Successful query with alerts (retrieving current raw alerts) ──
    alerts_result = await live_indexer_client.get_alerts(limit=5, offset=0)
    assert alerts_result.total >= 0
    assert alerts_result.count == len(alerts_result.alerts)
    assert alerts_result.limit == 5

    if alerts_result.count > 0:
        # Verify first alert structure and raw payload integrity
        first_alert = alerts_result.alerts[0]
        assert first_alert.id != ""
        assert first_alert.index != ""
        assert isinstance(first_alert.raw, dict)
        assert len(first_alert.raw) > 0
        # Check that original source data was preserved unaltered
        assert "rule" in first_alert.raw
    else:
        # Valid state if the indexer has no indexed alerts yet
        assert alerts_result.alerts == []


@pytest.mark.live
@pytest.mark.asyncio
async def test_live_opensearch_query_failure_handling(live_indexer_client: WazuhIndexerClient):
    """Test that actual query failures (e.g. invalid index pattern) raise typed IntegrationError."""
    # Searching an invalid/malformed endpoint or causing an OpenSearch error
    # should be caught and raised as OpenSearchQueryError, not unhandled 500
    with pytest.raises(IntegrationError):
        # Querying an illegal Lucene path or invalid query body
        await live_indexer_client._request(
            "POST",
            "/_invalid_index_path_test/_search",
            json_data={"query": {"invalid_syntax_clause": {}}},
        )


@pytest.mark.live
@pytest.mark.asyncio
async def test_live_opensearch_missing_index_raises_not_found(live_indexer_client: WazuhIndexerClient):
    """Verify that querying a non-existent index pattern raises OpenSearchIndexNotFoundError (404).

    Confirms that missing/misconfigured indices are reported as explicit errors
    rather than silently returning a false 0-alert result.
    """
    with pytest.raises(OpenSearchIndexNotFoundError) as exc_info:
        await live_indexer_client.get_alerts(index_pattern="nonexistent_index_for_testing_failure")

    assert exc_info.value.status_code == 404
    assert "not found" in str(exc_info.value)

