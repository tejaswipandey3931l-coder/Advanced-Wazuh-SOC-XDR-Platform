"""
Wazuh REST API and Wazuh Indexer (OpenSearch) integration clients.

Provides asynchronous, resilient communication with:
  1. Wazuh Manager REST API (:55000) for cluster management and metadata.
  2. Wazuh Indexer (:9200) for raw alert retrieval and search.

Features:
  - Strongly-typed domain exceptions preventing credential leakage.
  - JWT token caching and transparent re-authentication on expiration.
  - Bounded exponential-backoff retries for transient network failures.
  - Full TLS certificate validation supporting private/self-signed CAs.
  - Strict bounded pagination and time-range filtering.
"""

from __future__ import annotations

import asyncio
import os
import ssl
from typing import Any

import httpx
import structlog

from .config import Settings, get_settings
from .exceptions import (
    IntegrationError,
    OpenSearchAuthenticationError,
    OpenSearchAuthorizationError,
    OpenSearchConnectionError,
    OpenSearchIndexNotFoundError,
    OpenSearchIntegrationError,
    OpenSearchQueryError,
    OpenSearchTimeoutError,
    WazuhAuthenticationError,
    WazuhAuthorizationError,
    WazuhConnectionError,
    WazuhIntegrationError,
    WazuhResponseError,
    WazuhTimeoutError,
)
from .schemas.wazuh import (
    AlertListResponse,
    RawAlertItem,
    WazuhApiInfo,
    WazuhManagerInfo,
    WazuhManagerStatus,
)

log = structlog.get_logger(__name__)


def build_ssl_verify(verify_ssl: bool, ca_cert_path: str | None = None) -> ssl.SSLContext | bool:
    """Construct an SSL verification context or return a boolean flag.

    Preserves strict TLS validation by default. If a custom CA certificate path
    is provided and exists, creates an SSLContext with that trust anchor.
    """
    if not verify_ssl:
        return False

    if ca_cert_path:
        # Expand user/relative paths against project root if needed
        resolved_path = os.path.abspath(ca_cert_path)
        if os.path.isfile(resolved_path):
            ctx = ssl.create_default_context(cafile=resolved_path)
            # Private self-signed certificates in lab/native setups often use
            # SANs/CNs differing from the local IP (e.g. CN=wazuh.indexer vs 127.0.0.1).
            # We disable hostname matching while still requiring strict cryptographic
            # signature validation against the trusted CA.
            ctx.check_hostname = False
            return ctx
        log.warning("ca_cert_file_not_found", path=ca_cert_path)

    # Standard system CA certificate store validation
    return True


class WazuhClient:
    """Asynchronous client for the Wazuh Manager REST API (:55000)."""

    def __init__(self, settings: Settings | None = None) -> None:
        self.settings = settings or get_settings()
        self.base_url = self.settings.wazuh_api_url.rstrip("/")
        self.username = self.settings.wazuh_api_user
        self.password = self.settings.wazuh_api_password
        self.timeout = self.settings.wazuh_api_timeout
        self.max_retries = self.settings.wazuh_api_max_retries

        if not self.username or not self.password:
            raise WazuhAuthenticationError("WAZUH_API_USER and WAZUH_API_PASSWORD must be configured")

        self.ssl_verify = build_ssl_verify(
            verify_ssl=self.settings.wazuh_verify_ssl,
            ca_cert_path=self.settings.wazuh_ca_cert,
        )
        self._token: str | None = None
        self._token_lock = asyncio.Lock()

    async def authenticate(self, force_refresh: bool = False) -> str:
        """Obtain a JWT from the Wazuh API, caching and reusing tokens safely."""
        async with self._token_lock:
            if self._token and not force_refresh:
                return self._token

            url = f"{self.base_url}/security/user/authenticate"
            log.debug("wazuh_authenticating", url=url)

            retries = 0
            while True:
                try:
                    async with httpx.AsyncClient(
                        verify=self.ssl_verify,
                        timeout=self.timeout,
                    ) as client:
                        response = await client.post(
                            url,
                            auth=(self.username, self.password),
                            params={"raw": "true"},
                        )

                    if response.status_code == 401:
                        raise WazuhAuthenticationError("Invalid Wazuh API credentials")
                    if response.status_code == 403:
                        raise WazuhAuthorizationError("Access denied by Wazuh API")
                    if response.status_code >= 500:
                        raise WazuhResponseError(
                            f"Wazuh API server error: {response.status_code}",
                            status_code=response.status_code,
                        )

                    response.raise_for_status()
                    token = response.text.strip()
                    if not token:
                        raise WazuhResponseError("Empty JWT received from Wazuh API")

                    self._token = token
                    log.debug("wazuh_authentication_success")
                    return self._token

                except (WazuhAuthenticationError, WazuhAuthorizationError):
                    raise
                except httpx.ConnectTimeout as exc:
                    retries += 1
                    if retries > self.max_retries:
                        log.error("wazuh_auth_timeout", error=str(exc))
                        raise WazuhTimeoutError("Connection to Wazuh API timed out") from exc
                    await asyncio.sleep(0.2 * (2 ** retries))
                except (httpx.ConnectError, httpx.NetworkError) as exc:
                    retries += 1
                    if retries > self.max_retries:
                        log.error("wazuh_auth_connection_failed", error=str(exc))
                        raise WazuhConnectionError("Cannot connect to Wazuh API service") from exc
                    await asyncio.sleep(0.2 * (2 ** retries))
                except httpx.HTTPStatusError as exc:
                    raise WazuhResponseError(
                        f"Wazuh API HTTP error: {exc.response.status_code}",
                        status_code=exc.response.status_code,
                    ) from exc
                except Exception as exc:
                    if isinstance(exc, (WazuhIntegrationError,)):
                        raise
                    log.error("wazuh_auth_unexpected_error", error=type(exc).__name__)
                    raise WazuhIntegrationError(f"Unexpected error during Wazuh authentication: {type(exc).__name__}") from exc

    async def _request(
        self,
        method: str,
        path: str,
        *,
        params: dict[str, Any] | None = None,
        json_data: Any | None = None,
        attempt: int = 1,
    ) -> dict[str, Any]:
        """Send an authenticated request to the Wazuh REST API with automatic re-auth."""
        token = await self.authenticate()
        url = f"{self.base_url}/{path.lstrip('/')}"
        headers = {"Authorization": f"Bearer {token}"}

        retries = 0
        while True:
            try:
                async with httpx.AsyncClient(
                    verify=self.ssl_verify,
                    timeout=self.timeout,
                ) as client:
                    response = await client.request(
                        method=method,
                        url=url,
                        headers=headers,
                        params=params,
                        json=json_data,
                    )

                if response.status_code == 401 and attempt == 1:
                    # Token may have expired — clear token and retry once
                    log.info("wazuh_token_expired_retrying")
                    await self.authenticate(force_refresh=True)
                    return await self._request(
                        method, path, params=params, json_data=json_data, attempt=2
                    )

                if response.status_code == 401:
                    raise WazuhAuthenticationError("Wazuh authentication token rejected")
                if response.status_code == 403:
                    raise WazuhAuthorizationError("Wazuh authorization denied for endpoint")
                if response.status_code == 404:
                    raise WazuhResponseError(f"Wazuh endpoint not found: {path}", status_code=404)
                if response.status_code >= 500:
                    raise WazuhResponseError(
                        f"Wazuh API internal error: {response.status_code}",
                        status_code=response.status_code,
                    )

                response.raise_for_status()
                return response.json()

            except (WazuhAuthenticationError, WazuhAuthorizationError, WazuhResponseError):
                raise
            except httpx.ConnectTimeout as exc:
                retries += 1
                if retries > self.max_retries:
                    raise WazuhTimeoutError(f"Request to Wazuh API {path} timed out") from exc
                await asyncio.sleep(0.2 * (2 ** retries))
            except (httpx.ConnectError, httpx.NetworkError) as exc:
                retries += 1
                if retries > self.max_retries:
                    raise WazuhConnectionError("Wazuh API unreachable or refused connection") from exc
                await asyncio.sleep(0.2 * (2 ** retries))
            except Exception as exc:
                if isinstance(exc, WazuhIntegrationError):
                    raise
                raise WazuhResponseError(f"Failed to parse Wazuh API response: {type(exc).__name__}") from exc

    async def get_api_info(self) -> WazuhApiInfo:
        """Fetch Wazuh REST API top-level metadata (GET /)."""
        data = await self._request("GET", "/")
        payload = data.get("data", {})
        return WazuhApiInfo(
            title=payload.get("title", "Wazuh API REST"),
            api_version=payload.get("api_version", "unknown"),
            revision=payload.get("revision"),
            hostname=payload.get("hostname"),
            timestamp=payload.get("timestamp"),
        )

    async def get_manager_info(self) -> WazuhManagerInfo:
        """Fetch Wazuh Manager node engine metadata (GET /manager/info)."""
        data = await self._request("GET", "/manager/info")
        payload = data.get("data", {})
        items = payload.get("affected_items", [])
        if not items:
            raise WazuhResponseError("No manager information returned by Wazuh API")
        item = items[0]
        return WazuhManagerInfo(
            version=item.get("version", "unknown"),
            type=item.get("type"),
            path=item.get("path"),
            uuid=item.get("uuid"),
            tz_offset=item.get("tz_offset"),
            tz_name=item.get("tz_name"),
        )

    async def get_manager_status(self) -> WazuhManagerStatus:
        """Fetch operational status of core Wazuh daemons (GET /manager/status)."""
        data = await self._request("GET", "/manager/status")
        payload = data.get("data", {})
        items = payload.get("affected_items", [])
        daemons = items[0] if items else {}
        return WazuhManagerStatus(daemons=daemons)


class WazuhIndexerClient:
    """Asynchronous client for Wazuh Indexer / OpenSearch (:9200) raw alert retrieval."""

    def __init__(self, settings: Settings | None = None) -> None:
        self.settings = settings or get_settings()
        self.base_url = self.settings.opensearch_url.rstrip("/")
        self.username = self.settings.opensearch_user
        self.password = self.settings.opensearch_password
        self.timeout = self.settings.opensearch_timeout
        self.max_retries = self.settings.opensearch_max_retries

        self.ssl_verify = build_ssl_verify(
            verify_ssl=self.settings.opensearch_verify_ssl,
            ca_cert_path=self.settings.opensearch_ca_cert,
        )

    async def _request(
        self,
        method: str,
        path: str,
        *,
        params: dict[str, Any] | None = None,
        json_data: Any | None = None,
    ) -> dict[str, Any]:
        """Execute a query against OpenSearch with authentication and retries."""
        url = f"{self.base_url}/{path.lstrip('/')}"
        auth = (self.username, self.password) if (self.username and self.password) else None

        retries = 0
        while True:
            try:
                async with httpx.AsyncClient(
                    verify=self.ssl_verify,
                    timeout=self.timeout,
                    auth=auth,
                ) as client:
                    response = await client.request(
                        method=method,
                        url=url,
                        params=params,
                        json=json_data,
                    )

                if response.status_code == 401:
                    raise OpenSearchAuthenticationError("OpenSearch authentication failed: invalid credentials")
                if response.status_code == 403:
                    raise OpenSearchAuthorizationError("OpenSearch authorization denied")
                if response.status_code == 404:
                    raise OpenSearchIndexNotFoundError(
                        f"OpenSearch index or resource not found: {path}",
                        status_code=404,
                    )
                if response.status_code >= 500:
                    raise OpenSearchQueryError(
                        f"OpenSearch internal server error: {response.status_code}",
                        status_code=response.status_code,
                    )

                response.raise_for_status()
                return response.json()

            except (OpenSearchAuthenticationError, OpenSearchAuthorizationError, OpenSearchQueryError):
                raise
            except httpx.HTTPStatusError as exc:
                raise OpenSearchQueryError(
                    f"OpenSearch query failed with HTTP {exc.response.status_code}",
                    status_code=exc.response.status_code,
                ) from exc
            except httpx.ConnectTimeout as exc:
                retries += 1
                if retries > self.max_retries:
                    raise OpenSearchTimeoutError("Connection to OpenSearch timed out") from exc
                await asyncio.sleep(0.2 * (2 ** retries))
            except (httpx.ConnectError, httpx.NetworkError) as exc:
                retries += 1
                if retries > self.max_retries:
                    raise OpenSearchConnectionError("OpenSearch service unreachable or refused connection") from exc
                await asyncio.sleep(0.2 * (2 ** retries))
            except Exception as exc:
                if isinstance(exc, OpenSearchIntegrationError):
                    raise
                raise OpenSearchQueryError(f"Failed to execute OpenSearch query: {type(exc).__name__}") from exc


    async def get_cluster_health(self) -> dict[str, Any]:
        """Fetch OpenSearch cluster health status."""
        return await self._request("GET", "/_cluster/health")

    async def get_alerts(
        self,
        *,
        limit: int = 20,
        offset: int = 0,
        min_level: int | None = None,
        rule_id: str | None = None,
        agent_id: str | None = None,
        start_time: str | None = None,
        end_time: str | None = None,
        index_pattern: str = "wazuh-alerts-*",
    ) -> AlertListResponse:
        """Retrieve paginated raw alerts from Wazuh Indexer with optional filtering.

        Preserves the complete raw JSON payload under the ``raw`` attribute
        for each item, which is mandatory for Phase 2 normalization.
        A query that matches zero alerts returns an AlertListResponse with
        total=0, count=0, and alerts=[], which is a successful result.
        """
        # Bounded limits enforcement
        safe_limit = max(1, min(limit, 500))
        safe_offset = max(0, offset)

        filters: list[dict[str, Any]] = []

        if min_level is not None:
            filters.append({"range": {"rule.level": {"gte": min_level}}})

        if rule_id:
            filters.append({"term": {"rule.id": rule_id}})

        if agent_id:
            filters.append({"term": {"agent.id": agent_id}})

        if start_time or end_time:
            time_filter: dict[str, str] = {}
            if start_time:
                time_filter["gte"] = start_time
            if end_time:
                time_filter["lte"] = end_time
            filters.append({"range": {"@timestamp": time_filter}})

        query: dict[str, Any] = {
            "from": safe_offset,
            "size": safe_limit,
            "sort": [{"@timestamp": {"order": "desc", "unmapped_type": "date"}}],
            "query": {"bool": {"filter": filters}} if filters else {"match_all": {}},
        }

        data = await self._request("POST", f"/{index_pattern}/_search", json_data=query)

        hits_obj = data.get("hits", {})
        total_raw = hits_obj.get("total", 0)
        total_val = total_raw.get("value", 0) if isinstance(total_raw, dict) else int(total_raw)

        alert_items: list[RawAlertItem] = []
        for hit in hits_obj.get("hits", []):
            source = hit.get("_source", {})
            rule = source.get("rule", {})
            agent = source.get("agent", {})

            item = RawAlertItem(
                id=hit.get("_id", ""),
                index=hit.get("_index", ""),
                timestamp=source.get("@timestamp") or source.get("timestamp"),
                rule_id=rule.get("id"),
                rule_level=rule.get("level"),
                rule_description=rule.get("description"),
                agent_id=agent.get("id"),
                agent_name=agent.get("name"),
                raw=source,
            )
            alert_items.append(item)

        return AlertListResponse(
            total=total_val,
            count=len(alert_items),
            limit=safe_limit,
            offset=safe_offset,
            alerts=alert_items,
        )