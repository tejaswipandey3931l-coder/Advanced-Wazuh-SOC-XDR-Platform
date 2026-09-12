"""
Shared pytest fixtures for the Advanced Wazuh SOC test suite.

Phase 0 fixtures:
  - ``client``: an async HTTPX test client wired to the FastAPI app.
                Does NOT connect to a real database.  Use it to test
                endpoints that do not require DB access (e.g. /health).

Phase 1+ fixtures will add:
  - ``db_session``: an async SQLAlchemy session against a test PostgreSQL db.
  - ``redis_client``: a Redis test client.
"""

from __future__ import annotations

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient

from backend.app.main import app


@pytest_asyncio.fixture
async def client() -> AsyncClient:
    """Yield an async HTTPX test client bound to the FastAPI ASGI app.

    Uses ASGITransport to call handlers directly — no network socket is
    opened, making tests fast and hermetic.
    """
    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://testserver",
    ) as ac:
        yield ac
