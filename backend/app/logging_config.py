"""
Structured logging configuration using structlog.

Call ``configure_logging()`` once at application startup (in the lifespan
handler).  All modules then obtain a logger with::

    import structlog
    log = structlog.get_logger(__name__)
"""

from __future__ import annotations

import logging
import re
import sys
from typing import Any

import structlog

# Set of lowercase key substrings that indicate sensitive information
_SENSITIVE_KEYS: frozenset[str] = frozenset({
    "password",
    "token",
    "jwt",
    "secret",
    "authorization",
    "auth",
    "cookie",
    "api_key",
    "apikey",
    "credentials",
    "private_key",
})

_BEARER_PATTERN = re.compile(r"Bearer\s+([A-Za-z0-9\-._~+/]+=*)", re.IGNORECASE)


def redact_sensitive_data(val: Any) -> Any:
    """Recursively redact sensitive strings and mappings."""
    if isinstance(val, dict):
        return {
            k: ("[REDACTED]" if any(s in k.lower() for s in _SENSITIVE_KEYS) else redact_sensitive_data(v))
            for k, v in val.items()
        }
    if isinstance(val, (list, tuple)):
        return [redact_sensitive_data(item) for item in val]
    if isinstance(val, str):
        if _BEARER_PATTERN.search(val):
            return _BEARER_PATTERN.sub("Bearer [REDACTED]", val)
    return val


def redact_sensitive_processor(
    logger: Any, method_name: str, event_dict: dict[str, Any]
) -> dict[str, Any]:
    """Structlog processor that redacts passwords, tokens, and Authorization values."""
    for key in list(event_dict.keys()):
        lower_key = key.lower()
        if any(s in lower_key for s in _SENSITIVE_KEYS):
            event_dict[key] = "[REDACTED]"
        else:
            event_dict[key] = redact_sensitive_data(event_dict[key])
    return event_dict


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
        # Redact any passwords, tokens, or JWTs.
        redact_sensitive_processor,
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
