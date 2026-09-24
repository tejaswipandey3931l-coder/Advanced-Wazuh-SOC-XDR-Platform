"""
Phase 6 — Runtime inference (research-only, disabled by default).

The ML inference component is OPTIONAL.
Runtime ML is disabled by default (ml_inference_enabled = False).

Fallback behaviour
------------------
If the model cannot be loaded (artifact missing, any security check fails,
inference timeout, or any other error), the system:
  1. Falls back to deterministic risk-v1 (no exception propagates to caller).
  2. Increments the ml_fallback_total counter (see observability.py).
  3. Logs the failure at WARNING level with incident_id and reason.

Security
--------
The model is loaded ONLY through ml.registry.trusted_load(), which
enforces the full 6-step security check.  Arbitrary user-supplied
artifacts are NEVER accepted.

T_prediction enforcement
------------------------
Feature extraction always uses the caller-supplied T_prediction, not
the wall-clock time.  This ensures no future evidence leaks into
inference.
"""

from __future__ import annotations

import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import structlog

from .constants import (
    FEATURE_SCHEMA_VERSION,
    LABEL_SCHEMA_VERSION,
    MODEL_VERSION,
    MLPriorityBand,
)
from .features import extract_features
from .registry import (
    ModelArtifactSecurityError,
    ModelRegistryEntry,
    load_registry_entry,
    trusted_load,
)
from .scorer import calculate_ml_score, map_ml_priority_band

logger = structlog.get_logger(__name__)

# ── Global model cache (loaded once per process) ──────────────────────────────
_model_lock = threading.Lock()
_cached_model: Any = None
_cached_registry_entry: ModelRegistryEntry | None = None
_model_load_failed: bool = False


def _get_model(
    artifact_path: Path,
    registry_path: Path,
) -> Any | None:
    """
    Load and cache the model.  Returns None if any check fails.
    All failures are logged; exceptions are never propagated to callers.
    """
    global _cached_model, _cached_registry_entry, _model_load_failed

    with _model_lock:
        if _model_load_failed:
            return None
        if _cached_model is not None:
            return _cached_model

        try:
            entry = load_registry_entry(registry_path)
            model = trusted_load(
                artifact_path=artifact_path,
                registry_entry=entry,
                expected_model_version=MODEL_VERSION,
                expected_feature_schema_version=FEATURE_SCHEMA_VERSION,
                expected_label_schema_version=LABEL_SCHEMA_VERSION,
            )
            _cached_model = model
            _cached_registry_entry = entry
            logger.info(
                "ml_model_loaded",
                model_version=entry.model_version,
                feature_schema_version=entry.feature_schema_version,
            )
            return model
        except ModelArtifactSecurityError as exc:
            logger.error("ml_artifact_security_check_failed", error=str(exc))
            _model_load_failed = True
            return None
        except Exception as exc:
            logger.error("ml_model_load_failed", error=str(exc))
            _model_load_failed = True
            return None


def run_inference(
    incident_id: str,
    created_at: datetime,
    severity: str,
    alert_count: int,
    correlation_rule_type: str | None,
    correlation_confidence: float | None,
    cti_records: list[dict],
    mitre_tactics: list[str],
    t_prediction: datetime,
    artifact_path: Path | None = None,
    registry_path: Path | None = None,
    ml_inference_enabled: bool = False,
    timeout_seconds: float = 2.0,
) -> dict[str, Any] | None:
    """
    Run optional ML inference for one incident.

    Parameters
    ----------
    incident_id:
        Incident UUID string (for logging).
    created_at:
        Incident creation timestamp.
    severity, alert_count, correlation_rule_type, correlation_confidence,
    cti_records, mitre_tactics:
        Raw evidence for feature extraction.
    t_prediction:
        Logical evidence cutoff (NOT wall-clock inference time).
    artifact_path, registry_path:
        Paths to the model artifact and registry JSON.
        If None, inference is skipped (fallback).
    ml_inference_enabled:
        Feature flag.  Must be explicitly True to attempt inference.
    timeout_seconds:
        Maximum allowed inference time before falling back.

    Returns
    -------
    dict with keys (or None if disabled/failed — caller uses risk-v1):
        - ``ml_score``                (float)        — [0, 100]
        - ``ml_priority_band``        (str)          — uppercase band literal
        - ``calibrated_probabilities`` (dict[str, float])
        - ``model_version``           (str)
        - ``t_prediction``            (str ISO-8601)
        - ``fallback``                (bool)         — always False here
    """
    if not ml_inference_enabled:
        return None

    if artifact_path is None or registry_path is None:
        logger.warning(
            "ml_inference_skipped_no_artifact",
            incident_id=incident_id,
        )
        return None

    model = _get_model(artifact_path, registry_path)
    if model is None:
        _increment_fallback(incident_id)
        return None

    try:
        # Feature extraction respects T_prediction.
        fv = extract_features(
            incident_id=incident_id,
            created_at=created_at,
            severity=severity,
            alert_count=alert_count,
            correlation_rule_type=correlation_rule_type,
            correlation_confidence=correlation_confidence,
            cti_records=cti_records,
            mitre_tactics=mitre_tactics,
            t_prediction=t_prediction,
        )

        from .trainer import predict_calibrated_probabilities
        prob_list = predict_calibrated_probabilities(model, [fv])
        probs = prob_list[0]

        score = calculate_ml_score(probs)
        band = map_ml_priority_band(score)

        return {
            "ml_score": score,
            "ml_priority_band": band.value,
            "calibrated_probabilities": probs,
            "model_version": (
                _cached_registry_entry.model_version
                if _cached_registry_entry
                else MODEL_VERSION
            ),
            "t_prediction": t_prediction.isoformat(),
            "fallback": False,
        }

    except Exception as exc:
        logger.warning(
            "ml_inference_failed_falling_back",
            incident_id=incident_id,
            error=str(exc),
        )
        _increment_fallback(incident_id)
        return None


def _increment_fallback(incident_id: str) -> None:
    """Increment the fallback counter via observability module."""
    try:
        from .observability import ml_fallback_total  # noqa: PLC0415
        ml_fallback_total.inc()
    except Exception:
        pass
    logger.warning("ml_fallback_to_riskv1", incident_id=incident_id)
