"""
Event Normalization & ECS Mapping package for Advanced Wazuh SOC.
"""

from normalizer.categories import resolve_category_and_type
from normalizer.exceptions import (
    InvalidNetworkAddressError,
    InvalidTimestampError,
    MissingRequiredFieldError,
    NormalizationError,
)
from normalizer.schemas import (
    SOC_EVENT_NAMESPACE,
    NormalizationResult,
    NormalizedEventListResponse,
    NormalizedEventSchema,
    generate_event_id,
)
from normalizer.service import NormalizationService
from normalizer.wazuh_normalizer import EventNormalizer

__all__ = [
    "SOC_EVENT_NAMESPACE",
    "EventNormalizer",
    "InvalidNetworkAddressError",
    "InvalidTimestampError",
    "MissingRequiredFieldError",
    "NormalizationError",
    "NormalizationResult",
    "NormalizationService",
    "NormalizedEventListResponse",
    "NormalizedEventSchema",
    "generate_event_id",
    "resolve_category_and_type",
]
