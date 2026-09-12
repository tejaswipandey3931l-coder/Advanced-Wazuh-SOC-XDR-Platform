"""
Alembic environment configuration for the Advanced Wazuh SOC platform.

Uses the async SQLAlchemy engine (asyncpg) so that the same connection
string is used by both the application and migrations — no separate sync
driver is required.

The database URL is read from the SOC_DB_URL environment variable (or .env),
so credentials are never stored in this file or in alembic.ini.
"""

from __future__ import annotations

import asyncio
import os
import sys
from logging.config import fileConfig
from pathlib import Path

# ---------------------------------------------------------------------------
# Ensure the project root is on sys.path so that ``backend.app`` is importable
# when Alembic is run from the project root.
# ---------------------------------------------------------------------------
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from dotenv import load_dotenv

load_dotenv(PROJECT_ROOT / ".env")

from sqlalchemy import pool
from sqlalchemy.engine import Connection
from sqlalchemy.ext.asyncio import async_engine_from_config

from alembic import context

# ---------------------------------------------------------------------------
# Import ALL models so that Base.metadata is fully populated before Alembic
# attempts autogenerate.  The models __init__ takes care of this.
# ---------------------------------------------------------------------------
from backend.app.models import Base  # noqa: F401 — registers all table metadata
import backend.app.models  # noqa: F401

# ---------------------------------------------------------------------------
# Alembic config object
# ---------------------------------------------------------------------------
config = context.config

if config.config_file_name is not None:
    fileConfig(config.config_file_name)

# Inject the database URL from the environment, overriding the placeholder
# in alembic.ini.  This keeps credentials out of version control.
db_url = os.environ.get("SOC_DB_URL")
if not db_url:
    raise RuntimeError(
        "SOC_DB_URL environment variable is not set. "
        "Add it to your .env file before running Alembic."
    )
config.set_main_option("sqlalchemy.url", db_url)

target_metadata = Base.metadata


# ---------------------------------------------------------------------------
# Offline migrations (generate SQL without connecting to DB)
# ---------------------------------------------------------------------------
def run_migrations_offline() -> None:
    """Run migrations in 'offline' mode.

    Generates SQL that can be reviewed and applied manually.
    Useful for DBAs or air-gapped environments.
    """
    url = config.get_main_option("sqlalchemy.url")
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        compare_type=True,
        compare_server_default=True,
    )
    with context.begin_transaction():
        context.run_migrations()


# ---------------------------------------------------------------------------
# Online migrations (connects to the live database)
# ---------------------------------------------------------------------------
def do_run_migrations(connection: Connection) -> None:
    context.configure(
        connection=connection,
        target_metadata=target_metadata,
        compare_type=True,
        compare_server_default=True,
    )
    with context.begin_transaction():
        context.run_migrations()


async def run_async_migrations() -> None:
    """Run migrations using the asyncpg driver via asyncio."""
    connectable = async_engine_from_config(
        config.get_section(config.config_ini_section, {}),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )
    async with connectable.connect() as connection:
        await connection.run_sync(do_run_migrations)
    await connectable.dispose()


def run_migrations_online() -> None:
    """Entry point for online migrations."""
    asyncio.run(run_async_migrations())


# ---------------------------------------------------------------------------
# Dispatch
# ---------------------------------------------------------------------------
if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
