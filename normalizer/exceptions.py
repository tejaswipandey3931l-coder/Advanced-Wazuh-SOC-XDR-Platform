"""
Domain exceptions for the event normalization engine.

These exceptions cleanly isolate transformation, format, and schema validation
errors from general infrastructure failures.
"""

from __future__ import annotations


class NormalizationError(Exception):
    """Base exception for all normalization failures."""

    def __init__(self, message: str) -> None:
        super().__init__(message)
        self.message = message


class MissingRequiredFieldError(NormalizationError):
    """Raised when an input alert lacks mandatory identity or rule fields."""
    pass


class InvalidTimestampError(NormalizationError):
    """Raised when a timestamp cannot be parsed into a valid UTC datetime."""
    pass


class InvalidNetworkAddressError(NormalizationError):
    """Raised when an IP address or port string violates networking specifications."""
    pass
