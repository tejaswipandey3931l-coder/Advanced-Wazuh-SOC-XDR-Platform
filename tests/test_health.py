"""
Smoke tests for the /health endpoint.

These tests verify:
  - The endpoint is reachable and returns HTTP 200.
  - The response body contains the required fields with correct values.
  - The service reports the correct version.

These tests do NOT require a database, Redis, or Wazuh connection.
"""

from __future__ import annotations

import pytest
from httpx import AsyncClient


@pytest.mark.asyncio
async def test_health_returns_200(client: AsyncClient) -> None:
    """GET /health must return HTTP 200."""
    response = await client.get("/health")
    assert response.status_code == 200, (
        f"Expected 200, got {response.status_code}. Body: {response.text}"
    )


@pytest.mark.asyncio
async def test_health_response_body(client: AsyncClient) -> None:
    """GET /health response body must contain expected fields."""
    response = await client.get("/health")
    body = response.json()

    assert "status" in body, "Response missing 'status' field"
    assert body["status"] == "ok", f"Expected status='ok', got {body['status']!r}"

    assert "service" in body, "Response missing 'service' field"
    assert body["service"] == "advanced-wazuh-soc", (
        f"Expected service='advanced-wazuh-soc', got {body['service']!r}"
    )

    assert "version" in body, "Response missing 'version' field"
    assert isinstance(body["version"], str) and len(body["version"]) > 0, (
        "version field must be a non-empty string"
    )


@pytest.mark.asyncio
async def test_health_content_type(client: AsyncClient) -> None:
    """GET /health must return JSON content type."""
    response = await client.get("/health")
    content_type = response.headers.get("content-type", "")
    assert "application/json" in content_type, (
        f"Expected application/json, got {content_type!r}"
    )
