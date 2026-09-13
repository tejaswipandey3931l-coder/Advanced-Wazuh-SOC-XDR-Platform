"""
Correlation package for Advanced Wazuh SOC/XDR.

Pure rule matching engine, sliding window state management, and incident correlation.
"""

from .engine import CorrelationEngine
from .models import (
    CorrelationMatch,
    CorrelationRuleDefinition,
    RuleType,
    SequenceStepDefinition,
    WindowItem,
)
from .rules import RuleRegistry
from .service import CorrelationService
from .state import (
    InMemoryWindowStateStore,
    RedisWindowStateStore,
    WindowStateStore,
)

__all__ = [
    "CorrelationEngine",
    "CorrelationRuleDefinition",
    "CorrelationMatch",
    "RuleType",
    "SequenceStepDefinition",
    "WindowItem",
    "RuleRegistry",
    "CorrelationService",
    "WindowStateStore",
    "InMemoryWindowStateStore",
    "RedisWindowStateStore",
]
