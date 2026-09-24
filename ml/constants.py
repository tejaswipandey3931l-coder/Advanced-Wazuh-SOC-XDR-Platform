"""
Phase 6 — Shared constants, schema versions, and enumerations.

These values are FROZEN once a model artifact is registered.  Any change
to feature/label schemas requires a version bump, which forces artifact
re-validation.
"""

from __future__ import annotations

import enum

# ── Schema versions ──────────────────────────────────────────────────────────
# Increment FEATURE_SCHEMA_VERSION whenever the feature vector definition
# changes (new features, removed features, altered encoding).
FEATURE_SCHEMA_VERSION: str = "1.0.0"

# Increment LABEL_SCHEMA_VERSION whenever the label set or ordinal mapping
# changes.
LABEL_SCHEMA_VERSION: str = "1.0.0"

# Increment MODEL_VERSION whenever a new model is trained and registered.
MODEL_VERSION: str = "0.1.0"

# ── Ordinal class weights (deterministic ordinal expected-value mapping) ─────
# Used by calculate_ml_score() to convert calibrated class probabilities to
# a scalar score in [0, 100].
#
# INFORMATIONAL = 0, LOW = 25, MEDIUM = 50, HIGH = 75, CRITICAL = 100
#
# The keys are the canonical string values stored in the database and
# returned by the API (uppercase, matching PriorityBand in risk-v1).
CLASS_ORDINAL_WEIGHTS: dict[str, float] = {
    "INFORMATIONAL": 0.0,
    "LOW": 25.0,
    "MEDIUM": 50.0,
    "HIGH": 75.0,
    "CRITICAL": 100.0,
}

# Canonical ordering for the 5-class problem (ascending severity).
PRIORITY_CLASS_ORDER: list[str] = [
    "INFORMATIONAL",
    "LOW",
    "MEDIUM",
    "HIGH",
    "CRITICAL",
]

# ml_score → priority band thresholds (same as risk-v1 PriorityBand).
#   [0, 20)    → INFORMATIONAL
#   [20, 40)   → LOW
#   [40, 60)   → MEDIUM
#   [60, 80)   → HIGH
#   [80, 100]  → CRITICAL
ML_PRIORITY_THRESHOLDS: list[tuple[float, str]] = [
    (20.0, "INFORMATIONAL"),
    (40.0, "LOW"),
    (60.0, "MEDIUM"),
    (80.0, "HIGH"),
    (float("inf"), "CRITICAL"),
]


class DatasetStatus(str, enum.Enum):
    """Pipeline status after dataset construction and sufficiency validation."""

    SUFFICIENT = "SUFFICIENT"
    INSUFFICIENT = "INSUFFICIENT"
    UNKNOWN = "UNKNOWN"


class LabelType(str, enum.Enum):
    """Provenance classification for incident-level ground-truth labels."""

    TRUE_GROUND_TRUTH = "TRUE_GROUND_TRUTH"
    ANALYST_LABEL = "ANALYST_LABEL"
    WEAK_LABEL = "WEAK_LABEL"
    UNKNOWN = "UNKNOWN"


class MLPriorityBand(str, enum.Enum):
    """ML-derived priority band (identical literals to risk-v1 PriorityBand)."""

    INFORMATIONAL = "INFORMATIONAL"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"
