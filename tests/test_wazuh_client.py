"""
Unit tests for Wazuh REST API and Wazuh Indexer (OpenSearch) clients.

Tests use mocks to ensure no network calls are made and run deterministically.
"""

from __future__ import annotations

import ssl
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

from backend.app.config import Settings
from backend.app.exceptions import (
    OpenSearchAuthenticationError,
    OpenSearchAuthorizationError,
    OpenSearchConnectionError,
    OpenSearchIndexNotFoundError,
    OpenSearchQueryError,
    OpenSearchTimeoutError,
    WazuhAuthenticationError,
    WazuhAuthorizationError,
    WazuhConnectionError,
    WazuhResponseError,
    WazuhTimeoutError,
)
from backend.app.logging_config import redact_sensitive_data, redact_sensitive_processor
from backend.app.schemas.wazuh import AlertListResponse, WazuhApiInfo, WazuhManagerInfo, WazuhManagerStatus
from backend.app.wazuh_client import WazuhClient, WazuhIndexerClient, build_ssl_verify


@pytest.fixture
def mock_settings() -> Settings:
    """Provide isolated Settings for testing with dummy credentials."""
    return Settings(
        wazuh_api_url="https://wazuh.test:55000",
        wazuh_api_user="test_wazuh_user",
        wazuh_api_password="test_wazuh_password",
        wazuh_verify_ssl=True,
        wazuh_ca_cert=None,
        wazuh_api_timeout=2.0,
        wazuh_api_max_retries=1,
        soc_db_url="postgresql+asyncpg://user:pass@localhost:5432/test_db",
        opensearch_url="https://opensearch.test:9200",
        opensearch_user="test_os_user",
        opensearch_password="test_os_password",
        opensearch_verify_ssl=True,
        opensearch_ca_cert=None,
        opensearch_timeout=2.0,
        opensearch_max_retries=1,
    )



# ── TLS Configuration Tests ──────────────────────────────────────────────────


def test_build_ssl_verify_disabled():
    """Verify that verify_ssl=False returns False."""
    assert build_ssl_verify(verify_ssl=False) is False


def test_build_ssl_verify_system_default():
    """Verify that verify_ssl=True without CA cert returns True."""
    assert build_ssl_verify(verify_ssl=True, ca_cert_path=None) is True


def test_build_ssl_verify_missing_file():
    """Verify that non-existent CA path falls back to True with a warning."""
    assert build_ssl_verify(verify_ssl=True, ca_cert_path="/non/existent/ca.pem") is True


def test_build_ssl_verify_with_custom_ca(tmp_path):
    """Verify that a valid CA file creates an SSLContext with hostname check disabled."""
    # Create a minimal self-signed test cert
    ca_file = tmp_path / "ca.pem"
    # We can mock ssl.create_default_context to avoid invalid PEM parse errors
    with patch("ssl.create_default_context") as mock_ctx_factory:
        mock_ctx = MagicMock(spec=ssl.SSLContext)
        mock_ctx_factory.return_value = mock_ctx

        ca_file.write_text("DUMMY CERT")
        res = build_ssl_verify(verify_ssl=True, ca_cert_path=str(ca_file))

        assert res == mock_ctx
        assert mock_ctx.check_hostname is False
        mock_ctx_factory.assert_called_once_with(cafile=str(ca_file))


# ── WazuhClient Tests ─────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_wazuh_client_missing_credentials():
    """Verify that initializing WazuhClient without user/password raises WazuhAuthenticationError."""
    bad_settings = Settings(
        wazuh_api_user="",
        wazuh_api_password="",
        soc_db_url="postgresql+asyncpg://user:pass@localhost:5432/test_db",
    )
    with pytest.raises(WazuhAuthenticationError) as exc_info:
        WazuhClient(settings=bad_settings)
    assert "WAZUH_API_USER and WAZUH_API_PASSWORD must be configured" in str(exc_info.value)


@pytest.mark.asyncio
async def test_wazuh_client_authenticate_success(mock_settings):
    """Verify successful authentication caches the JWT token."""
    client = WazuhClient(settings=mock_settings)

    mock_resp = MagicMock(spec=httpx.Response)
    mock_resp.status_code = 200
    mock_resp.text = "jwt-token-12345\n"
    mock_resp.raise_for_status = MagicMock()

    with patch("httpx.AsyncClient.post", new_callable=AsyncMock) as mock_post:
        mock_post.return_value = mock_resp

        token1 = await client.authenticate()
        assert token1 == "jwt-token-12345"
        assert client._token == "jwt-token-12345"

        # Second call should reuse the cached token without calling post again
        token2 = await client.authenticate()
        assert token2 == "jwt-token-12345"
        mock_post.assert_called_once()


@pytest.mark.asyncio
async def test_wazuh_client_authenticate_401(mock_settings):
    """Verify that 401 during authentication raises WazuhAuthenticationError."""
    client = WazuhClient(settings=mock_settings)

    mock_resp = MagicMock(spec=httpx.Response)
    mock_resp.status_code = 401

    with patch("httpx.AsyncClient.post", new_callable=AsyncMock) as mock_post:
        mock_post.return_value = mock_resp
        with pytest.raises(WazuhAuthenticationError):
            await client.authenticate(force_refresh=True)


@pytest.mark.asyncio
async def test_wazuh_client_authenticate_403(mock_settings):
    """Verify that 403 during authentication raises WazuhAuthorizationError."""
    client = WazuhClient(settings=mock_settings)

    mock_resp = MagicMock(spec=httpx.Response)
    mock_resp.status_code = 403

    with patch("httpx.AsyncClient.post", new_callable=AsyncMock) as mock_post:
        mock_post.return_value = mock_resp
        with pytest.raises(WazuhAuthorizationError):
            await client.authenticate(force_refresh=True)


@pytest.mark.asyncio
async def test_wazuh_client_authenticate_timeout(mock_settings):
    """Verify that timeouts during authentication raise WazuhTimeoutError."""
    client = WazuhClient(settings=mock_settings)

    with patch("httpx.AsyncClient.post", new_callable=AsyncMock) as mock_post:
        mock_post.side_effect = httpx.ConnectTimeout("Connection timed out")
        with pytest.raises(WazuhTimeoutError):
            await client.authenticate(force_refresh=True)


@pytest.mark.asyncio
async def test_wazuh_client_authenticate_connect_error(mock_settings):
    """Verify that connection errors during authentication raise WazuhConnectionError."""
    client = WazuhClient(settings=mock_settings)

    with patch("httpx.AsyncClient.post", new_callable=AsyncMock) as mock_post:
        mock_post.side_effect = httpx.ConnectError("Connection refused")
        with pytest.raises(WazuhConnectionError):
            await client.authenticate(force_refresh=True)


@pytest.mark.asyncio
async def test_wazuh_client_request_token_refresh(mock_settings):
    """Verify that a 401 on an authenticated endpoint triggers token refresh and retries once."""
    client = WazuhClient(settings=mock_settings)
    client._token = "stale-token"

    # First request gives 401, authentication gives new token, second request gives 200
    req_resp_401 = MagicMock(spec=httpx.Response)
    req_resp_401.status_code = 401

    auth_resp = MagicMock(spec=httpx.Response)
    auth_resp.status_code = 200
    auth_resp.text = "refreshed-token-99999"
    auth_resp.raise_for_status = MagicMock()

    req_resp_200 = MagicMock(spec=httpx.Response)
    req_resp_200.status_code = 200
    req_resp_200.json.return_value = {"data": {"title": "Wazuh API REST", "api_version": "4.14.7"}}
    req_resp_200.raise_for_status = MagicMock()

    with patch("httpx.AsyncClient.request", new_callable=AsyncMock) as mock_req, \
         patch("httpx.AsyncClient.post", new_callable=AsyncMock) as mock_post:
        mock_req.side_effect = [req_resp_401, req_resp_200]
        mock_post.return_value = auth_resp

        res = await client._request("GET", "/")
        assert res["data"]["api_version"] == "4.14.7"
        assert client._token == "refreshed-token-99999"
        assert mock_req.call_count == 2


@pytest.mark.asyncio
async def test_wazuh_client_get_api_info(mock_settings):
    """Verify get_api_info parsing."""
    client = WazuhClient(settings=mock_settings)
    sample_response = {
        "data": {
            "title": "Wazuh API REST",
            "api_version": "4.14.7",
            "revision": "401407",
            "hostname": "kali-host",
            "timestamp": "2026-09-13T12:00:00Z",
        }
    }
    with patch.object(client, "_request", new_callable=AsyncMock) as mock_req:
        mock_req.return_value = sample_response
        info = await client.get_api_info()

        assert isinstance(info, WazuhApiInfo)
        assert info.title == "Wazuh API REST"
        assert info.api_version == "4.14.7"
        assert info.hostname == "kali-host"


@pytest.mark.asyncio
async def test_wazuh_client_get_manager_info(mock_settings):
    """Verify get_manager_info parsing."""
    client = WazuhClient(settings=mock_settings)
    sample_response = {
        "data": {
            "affected_items": [
                {
                    "version": "v4.14.7",
                    "type": "server",
                    "path": "/var/ossec",
                    "uuid": "test-uuid-1234",
                    "tz_name": "UTC",
                }
            ]
        }
    }
    with patch.object(client, "_request", new_callable=AsyncMock) as mock_req:
        mock_req.return_value = sample_response
        mgr = await client.get_manager_info()

        assert isinstance(mgr, WazuhManagerInfo)
        assert mgr.version == "v4.14.7"
        assert mgr.path == "/var/ossec"
        assert mgr.uuid == "test-uuid-1234"


@pytest.mark.asyncio
async def test_wazuh_client_get_manager_status(mock_settings):
    """Verify get_manager_status parsing."""
    client = WazuhClient(settings=mock_settings)
    sample_response = {
        "data": {
            "affected_items": [
                {
                    "wazuh-analysisd": "running",
                    "wazuh-remoted": "running",
                    "wazuh-syscheckd": "running",
                }
            ]
        }
    }
    with patch.object(client, "_request", new_callable=AsyncMock) as mock_req:
        mock_req.return_value = sample_response
        status = await client.get_manager_status()

        assert isinstance(status, WazuhManagerStatus)
        assert status.daemons["wazuh-analysisd"] == "running"


# ── WazuhIndexerClient Tests ──────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_opensearch_client_auth_error(mock_settings):
    """Verify OpenSearch 401 raises OpenSearchAuthenticationError."""
    client = WazuhIndexerClient(settings=mock_settings)
    mock_resp = MagicMock(spec=httpx.Response)
    mock_resp.status_code = 401

    with patch("httpx.AsyncClient.request", new_callable=AsyncMock) as mock_req:
        mock_req.return_value = mock_resp
        with pytest.raises(OpenSearchAuthenticationError):
            await client._request("GET", "/_cluster/health")


@pytest.mark.asyncio
async def test_opensearch_client_auth_forbidden(mock_settings):
    """Verify OpenSearch 403 raises OpenSearchAuthorizationError."""
    client = WazuhIndexerClient(settings=mock_settings)
    mock_resp = MagicMock(spec=httpx.Response)
    mock_resp.status_code = 403

    with patch("httpx.AsyncClient.request", new_callable=AsyncMock) as mock_req:
        mock_req.return_value = mock_resp
        with pytest.raises(OpenSearchAuthorizationError):
            await client._request("GET", "/_cluster/health")


@pytest.mark.asyncio
async def test_opensearch_client_timeout(mock_settings):
    """Verify OpenSearch timeout raises OpenSearchTimeoutError."""
    client = WazuhIndexerClient(settings=mock_settings)

    with patch("httpx.AsyncClient.request", new_callable=AsyncMock) as mock_req:
        mock_req.side_effect = httpx.ConnectTimeout("Timeout connecting to OpenSearch")
        with pytest.raises(OpenSearchTimeoutError):
            await client._request("GET", "/_cluster/health")


@pytest.mark.asyncio
async def test_opensearch_client_connection_error(mock_settings):
    """Verify OpenSearch connection refused raises OpenSearchConnectionError."""
    client = WazuhIndexerClient(settings=mock_settings)

    with patch("httpx.AsyncClient.request", new_callable=AsyncMock) as mock_req:
        mock_req.side_effect = httpx.ConnectError("Connection refused")
        with pytest.raises(OpenSearchConnectionError):
            await client._request("GET", "/_cluster/health")


@pytest.mark.asyncio
async def test_opensearch_client_query_error_500(mock_settings):
    """Verify OpenSearch 500 error raises OpenSearchQueryError."""
    client = WazuhIndexerClient(settings=mock_settings)
    mock_resp = MagicMock(spec=httpx.Response)
    mock_resp.status_code = 500

    with patch("httpx.AsyncClient.request", new_callable=AsyncMock) as mock_req:
        mock_req.return_value = mock_resp
        with pytest.raises(OpenSearchQueryError):
            await client._request("GET", "/_cluster/health")


@pytest.mark.asyncio
async def test_opensearch_get_alerts_populated(mock_settings):
    """Verify get_alerts correctly maps hits into RawAlertItems with intact raw payload."""
    client = WazuhIndexerClient(settings=mock_settings)

    raw_alert_data = {
        "@timestamp": "2026-09-13T10:00:00.000Z",
        "rule": {
            "id": "5715",
            "level": 10,
            "description": "SSHD authentication failed",
        },
        "agent": {
            "id": "001",
            "name": "kali-agent",
        },
        "data": {
            "srcip": "192.168.1.100",
            "dstuser": "root",
        },
    }

    mock_os_response = {
        "hits": {
            "total": {"value": 1, "relation": "eq"},
            "hits": [
                {
                    "_id": "alert-doc-001",
                    "_index": "wazuh-alerts-4.x-2026.09.13",
                    "_source": raw_alert_data,
                }
            ],
        }
    }

    with patch.object(client, "_request", new_callable=AsyncMock) as mock_req:
        mock_req.return_value = mock_os_response

        res = await client.get_alerts(limit=10, offset=0, min_level=7, rule_id="5715")

        assert isinstance(res, AlertListResponse)
        assert res.total == 1
        assert res.count == 1
        assert res.limit == 10
        assert res.offset == 0
        assert len(res.alerts) == 1

        alert = res.alerts[0]
        assert alert.id == "alert-doc-001"
        assert alert.index == "wazuh-alerts-4.x-2026.09.13"
        assert alert.rule_id == "5715"
        assert alert.rule_level == 10
        assert alert.agent_name == "kali-agent"
        # Verify complete raw alert data is preserved without any loss
        assert alert.raw["data"]["srcip"] == "192.168.1.100"


@pytest.mark.asyncio
async def test_opensearch_get_alerts_zero_results_is_valid_success(mock_settings):
    """Verify that zero alerts returned is a valid successful result, NOT an error (Amendment 3)."""
    client = WazuhIndexerClient(settings=mock_settings)

    mock_os_response = {
        "hits": {
            "total": {"value": 0, "relation": "eq"},
            "hits": [],
        }
    }

    with patch.object(client, "_request", new_callable=AsyncMock) as mock_req:
        mock_req.return_value = mock_os_response

        res = await client.get_alerts(limit=50, offset=0, min_level=12)

        assert isinstance(res, AlertListResponse)
        assert res.total == 0
        assert res.count == 0
        assert res.limit == 50
        assert res.offset == 0
        assert res.alerts == []


@pytest.mark.asyncio
async def test_opensearch_get_alerts_404_raises_index_not_found_error(mock_settings):
    """Verify that a 404 (misconfigured or missing index) raises OpenSearchIndexNotFoundError.

    Ensures that genuine infrastructure or configuration issues are NOT silently
    masked as zero-alert successful responses.
    """
    client = WazuhIndexerClient(settings=mock_settings)

    mock_resp = MagicMock(spec=httpx.Response)
    mock_resp.status_code = 404

    with patch("httpx.AsyncClient.request", new_callable=AsyncMock) as mock_req:
        mock_req.return_value = mock_resp

        with pytest.raises(OpenSearchIndexNotFoundError) as exc_info:
            await client.get_alerts()

        assert exc_info.value.status_code == 404
        assert "not found" in str(exc_info.value)



# ── Secret Redaction Tests ───────────────────────────────────────────────────


def test_redact_sensitive_processor_removes_secrets():
    """Verify that passwords, tokens, JWTs, and Bearer headers are redacted."""
    event_dict = {
        "event": "user_login",
        "wazuh_api_password": "supersecretpassword",
        "opensearch_password": "anothersecret",
        "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.dummy.sig",
        "nested": {
            "api_key": "sensitive_api_key_value",
            "safe_field": "visible_data",
        },
        "auth_header": "sensitive_auth_header",
        "log_message": "User sent Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9 to access API",
    }

    processed = redact_sensitive_processor(None, "info", event_dict)

    assert processed["wazuh_api_password"] == "[REDACTED]"
    assert processed["opensearch_password"] == "[REDACTED]"
    assert processed["token"] == "[REDACTED]"
    assert processed["nested"]["api_key"] == "[REDACTED]"
    assert processed["nested"]["safe_field"] == "visible_data"
    assert processed["auth_header"] == "[REDACTED]"
    assert "Bearer [REDACTED]" in processed["log_message"]

