"""
SQLAlchemy async database engine and session factory.

Use ``get_db()`` as a FastAPI dependency to obtain an ``AsyncSession``
within a request context.  Direct engine access is available via ``engine``
for Alembic and health-check probes.
"""

from __future__ import annotations

from collections.abc import AsyncGenerator

from sqlalchemy.ext.asyncio import (
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from .config import get_settings

settings = get_settings()

# ---------------------------------------------------------------------------
# Engine — created once at import time.
# pool_pre_ping=True drops stale connections automatically (e.g. after DB
# restart), which is important for long-running services.
# ---------------------------------------------------------------------------
engine = create_async_engine(
    settings.soc_db_url,
    echo=settings.soc_db_echo,
    pool_size=settings.soc_db_pool_size,
    max_overflow=settings.soc_db_max_overflow,
    pool_pre_ping=True,
)

# ---------------------------------------------------------------------------
# Session factory
# expire_on_commit=False prevents lazy-load errors after commit when the
# session is already closed (common pattern in async FastAPI handlers).
# ---------------------------------------------------------------------------
AsyncSessionLocal: async_sessionmaker[AsyncSession] = async_sessionmaker(
    engine,
    expire_on_commit=False,
    class_=AsyncSession,
)
async_session_factory = AsyncSessionLocal


# ---------------------------------------------------------------------------
# FastAPI dependency
# ---------------------------------------------------------------------------
async def get_db() -> AsyncGenerator[AsyncSession, None]:
    """Yield an ``AsyncSession`` and ensure it is closed after use."""
    async with AsyncSessionLocal() as session:
        try:
            yield session
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()
