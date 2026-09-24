"""
Phase 6 ML Prioritization Package.

Provides an independent, research-grade ML prioritization signal for
security incidents.  This package is entirely separate from the
deterministic risk-v1 engine (Phase 5) and never modifies it.

Package layout
--------------
ml/
  __init__.py          — public re-exports
  constants.py         — shared enumerations, schema versions
  features.py          — deterministic, T_prediction-safe feature extraction
  labels.py            — label validation and provenance
  dataset.py           — dataset construction pipeline
  splitter.py          — chronological train/val/test splitting
  leakage.py           — leakage detection and deduplication
  trainer.py           — model training and calibration
  scorer.py            — deterministic ml_score calculation
  registry.py          — model artifact registry and trusted-load
  evaluator.py         — offline evaluation metrics
  inference.py         — runtime inference (disabled by default)
  observability.py     — Prometheus metrics (no-op stubs when absent)
"""

from __future__ import annotations

from .constants import (
    FEATURE_SCHEMA_VERSION,
    LABEL_SCHEMA_VERSION,
    MODEL_VERSION,
    DatasetStatus,
    LabelType,
    MLPriorityBand,
)
from .scorer import calculate_ml_score

__all__ = [
    "FEATURE_SCHEMA_VERSION",
    "LABEL_SCHEMA_VERSION",
    "MODEL_VERSION",
    "DatasetStatus",
    "LabelType",
    "MLPriorityBand",
    "calculate_ml_score",
]
