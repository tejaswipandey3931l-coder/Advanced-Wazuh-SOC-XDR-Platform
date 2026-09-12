"""
Structured logging configuration using structlog.

Call ``configure_logging()`` once at application startup (in the lifespan
handler).  All modules then obtain a logger with::

    import structlog
    log = structlog.get_logger(__name__)
"""

from __future__ import annotations

import logging
import sys

import structlog


def configure_logging(debug: bool = False) -> None:
    """Configure structlog for the application.

    In debug mode  → coloured, human-readable console output.
    In production  → JSON lines (one JSON object per log record),
                     suitable for log aggregation pipelines.
    """
    level = logging.DEBUG if debug else logging.INFO

    # Configure the stdlib root logger so that third-party libraries that use
    # standard ``logging`` are captured and rendered by structlog.
    logging.basicConfig(
        format="%(message)s",
        stream=sys.stdout,
        level=level,
    )

    shared_processors: list[structlog.types.Processor] = [
        # Merge any context variables bound via structlog.contextvars.
        structlog.contextvars.merge_contextvars,
        # Add the log level name to every event dict.
        structlog.processors.add_log_level,
        # Render exceptions inline.
        structlog.processors.ExceptionRenderer(),
        # ISO-8601 UTC timestamp.
        structlog.processors.TimeStamper(fmt="iso", utc=True),
    ]

    if debug:
        # Pretty console output for local development.
        renderer: structlog.types.Processor = structlog.dev.ConsoleRenderer(
            exception_formatter=structlog.dev.plain_traceback,
        )
    else:
        # JSON output for production / log collectors.
        renderer = structlog.processors.JSONRenderer()

    structlog.configure(
        processors=shared_processors + [renderer],
        wrapper_class=structlog.make_filtering_bound_logger(level),
        context_class=dict,
        logger_factory=structlog.PrintLoggerFactory(),
        cache_logger_on_first_use=True,
    )
