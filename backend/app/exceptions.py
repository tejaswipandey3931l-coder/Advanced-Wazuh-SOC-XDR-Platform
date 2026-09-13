"""
Application-level domain exceptions for the Wazuh SOC platform.

These exceptions cleanly decouple external transport/network errors (HTTP, TLS,
socket) from application logic and API responses, ensuring sensitive details
(tokens, credentials, connection strings) are never leaked to callers.
"""

from __future__ import annotations


class IntegrationError(Exception):
    """Base exception for all external integration errors."""

    def __init__(self, message: str, *, status_code: int = 502) -> None:
        super().__init__(message)
        self.message = message
        self.status_code = status_code


# ── Wazuh REST API Exceptions ────────────────────────────────────────────────


class WazuhIntegrationError(IntegrationError):
    """Base exception for Wazuh REST API errors."""
    pass


class WazuhAuthenticationError(WazuhIntegrationError):
    """Raised when authentication against the Wazuh REST API fails (401 / bad credentials)."""

    def __init__(self, message: str = "Wazuh API authentication failed") -> None:
        super().__init__(message, status_code=401)


class WazuhAuthorizationError(WazuhIntegrationError):
    """Raised when the authenticated user lacks permissions for the requested action (403)."""

    def __init__(self, message: str = "Wazuh API authorization denied") -> None:
        super().__init__(message, status_code=403)


class WazuhConnectionError(WazuhIntegrationError):
    """Raised when the Wazuh REST API is unreachable or connection is refused."""

    def __init__(self, message: str = "Wazuh API service unavailable or unreachable") -> None:
        super().__init__(message, status_code=503)


class WazuhTimeoutError(WazuhIntegrationError):
    """Raised when a request to the Wazuh REST API times out."""

    def __init__(self, message: str = "Wazuh API request timed out") -> None:
        super().__init__(message, status_code=504)


class WazuhResponseError(WazuhIntegrationError):
    """Raised when the Wazuh REST API returns an unexpected payload or status."""

    def __init__(self, message: str = "Invalid response from Wazuh API", *, status_code: int = 502) -> None:
        super().__init__(message, status_code=status_code)


# ── OpenSearch / Wazuh Indexer Exceptions ─────────────────────────────────────


class OpenSearchIntegrationError(IntegrationError):
    """Base exception for OpenSearch / Wazuh Indexer errors."""
    pass


class OpenSearchAuthenticationError(OpenSearchIntegrationError):
    """Raised when authentication against OpenSearch fails (401)."""

    def __init__(self, message: str = "OpenSearch authentication failed") -> None:
        super().__init__(message, status_code=401)


class OpenSearchAuthorizationError(OpenSearchIntegrationError):
    """Raised when the user lacks authorization in OpenSearch (403)."""

    def __init__(self, message: str = "OpenSearch authorization denied") -> None:
        super().__init__(message, status_code=403)


class OpenSearchConnectionError(OpenSearchIntegrationError):
    """Raised when OpenSearch is unreachable or connection is refused."""

    def __init__(self, message: str = "OpenSearch service unavailable or unreachable") -> None:
        super().__init__(message, status_code=503)


class OpenSearchTimeoutError(OpenSearchIntegrationError):
    """Raised when an OpenSearch query times out."""

    def __init__(self, message: str = "OpenSearch query timed out") -> None:
        super().__init__(message, status_code=504)


class OpenSearchQueryError(OpenSearchIntegrationError):
    """Raised when an OpenSearch query fails or returns an error."""

    def __init__(self, message: str = "OpenSearch query failed", *, status_code: int = 502) -> None:
        super().__init__(message, status_code=status_code)


class OpenSearchIndexNotFoundError(OpenSearchQueryError):
    """Raised when an OpenSearch index, index pattern, or endpoint is not found (404).

    Prevents silent suppression of missing or misconfigured Wazuh alert indices.
    """

    def __init__(self, message: str = "OpenSearch index or resource not found", *, status_code: int = 404) -> None:
        super().__init__(message, status_code=status_code)

