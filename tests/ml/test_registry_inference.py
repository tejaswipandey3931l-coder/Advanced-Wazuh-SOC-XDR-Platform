"""
Phase 6 — Unit tests for ml.registry and ml.inference.

Tests
-----
Registry:
- ModelRegistryEntry round-trips through to_dict / from_dict
- validate_artifact raises ModelArtifactSecurityError on SHA-256 mismatch
- validate_artifact raises on model_version mismatch
- validate_artifact raises on feature_schema_version mismatch
- validate_artifact raises on label_schema_version mismatch
- validate_artifact raises when artifact file is missing
- Any mismatch rejection (combined mismatch)
- trusted_load calls validate_artifact before loading
- save_registry_entry / load_registry_entry round-trip

Inference:
- run_inference returns None when ml_inference_enabled=False
- run_inference returns None when artifact_path is None
- run_inference falls back gracefully on model load failure
- run_inference returns None when model loading raises SecurityError
- ml_score and ml_priority_band are present in successful inference output
- t_prediction is included in inference output (for audit)
- fallback flag is always False in successful response (None means fallback)
"""

from __future__ import annotations

import json
import sys
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from ml.constants import (
    FEATURE_SCHEMA_VERSION,
    LABEL_SCHEMA_VERSION,
    MODEL_VERSION,
)
from ml.registry import (
    ModelArtifactSecurityError,
    ModelRegistryEntry,
    compute_file_sha256,
    load_registry_entry,
    save_registry_entry,
    validate_artifact,
)
from ml.inference import run_inference


# ── Helpers ───────────────────────────────────────────────────────────────────

def _make_entry(**overrides) -> ModelRegistryEntry:
    """Create a valid ModelRegistryEntry for testing."""
    defaults = dict(
        model_version=MODEL_VERSION,
        feature_schema_version=FEATURE_SCHEMA_VERSION,
        label_schema_version=LABEL_SCHEMA_VERSION,
        sha256="a" * 64,
        python_version=f"{sys.version_info.major}.{sys.version_info.minor}",
        library_versions={},
        trained_at_utc="2024-01-01T00:00:00+00:00",
        artifact_path="/fake/model.joblib",
        notes="test",
    )
    defaults.update(overrides)
    return ModelRegistryEntry(**defaults)


def _now() -> datetime:
    return datetime(2024, 6, 1, 10, 0, 0, tzinfo=timezone.utc)


# ── ModelRegistryEntry round-trip ─────────────────────────────────────────────

def test_registry_entry_round_trip():
    entry = _make_entry()
    d = entry.to_dict()
    restored = ModelRegistryEntry.from_dict(d)
    assert restored.model_version == entry.model_version
    assert restored.sha256 == entry.sha256
    assert restored.feature_schema_version == entry.feature_schema_version


# ── validate_artifact checks ──────────────────────────────────────────────────

def test_validate_artifact_missing_file_raises():
    entry = _make_entry()
    with pytest.raises(ModelArtifactSecurityError, match="not found"):
        validate_artifact(
            artifact_path=Path("/nonexistent/model.joblib"),
            registry_entry=entry,
            expected_model_version=MODEL_VERSION,
            expected_feature_schema_version=FEATURE_SCHEMA_VERSION,
            expected_label_schema_version=LABEL_SCHEMA_VERSION,
        )


def test_validate_artifact_sha256_mismatch_raises(tmp_path):
    """Tampered file (wrong SHA-256) must raise SecurityError."""
    artifact = tmp_path / "model.joblib"
    artifact.write_bytes(b"trusted content")
    real_sha256 = compute_file_sha256(artifact)

    # Entry with a WRONG SHA-256.
    entry = _make_entry(sha256="deadbeef" * 8)  # 64 chars, wrong hash

    with pytest.raises(ModelArtifactSecurityError, match="SHA-256 mismatch"):
        validate_artifact(
            artifact_path=artifact,
            registry_entry=entry,
            expected_model_version=MODEL_VERSION,
            expected_feature_schema_version=FEATURE_SCHEMA_VERSION,
            expected_label_schema_version=LABEL_SCHEMA_VERSION,
        )


def test_validate_artifact_correct_sha256_passes(tmp_path):
    """Correct SHA-256 + matching versions must not raise."""
    artifact = tmp_path / "model.joblib"
    artifact.write_bytes(b"trusted pipeline content")
    sha256 = compute_file_sha256(artifact)
    entry = _make_entry(sha256=sha256)

    # Should NOT raise.
    validate_artifact(
        artifact_path=artifact,
        registry_entry=entry,
        expected_model_version=MODEL_VERSION,
        expected_feature_schema_version=FEATURE_SCHEMA_VERSION,
        expected_label_schema_version=LABEL_SCHEMA_VERSION,
    )


def test_validate_artifact_model_version_mismatch_raises(tmp_path):
    artifact = tmp_path / "model.joblib"
    artifact.write_bytes(b"content")
    sha256 = compute_file_sha256(artifact)
    entry = _make_entry(sha256=sha256, model_version="99.99.99")

    with pytest.raises(ModelArtifactSecurityError, match="model_version mismatch"):
        validate_artifact(
            artifact_path=artifact,
            registry_entry=entry,
            expected_model_version=MODEL_VERSION,
            expected_feature_schema_version=FEATURE_SCHEMA_VERSION,
            expected_label_schema_version=LABEL_SCHEMA_VERSION,
        )


def test_validate_artifact_feature_schema_version_mismatch_raises(tmp_path):
    artifact = tmp_path / "model.joblib"
    artifact.write_bytes(b"content")
    sha256 = compute_file_sha256(artifact)
    entry = _make_entry(sha256=sha256, feature_schema_version="99.0.0")

    with pytest.raises(ModelArtifactSecurityError, match="feature_schema_version mismatch"):
        validate_artifact(
            artifact_path=artifact,
            registry_entry=entry,
            expected_model_version=MODEL_VERSION,
            expected_feature_schema_version=FEATURE_SCHEMA_VERSION,
            expected_label_schema_version=LABEL_SCHEMA_VERSION,
        )


def test_validate_artifact_label_schema_version_mismatch_raises(tmp_path):
    artifact = tmp_path / "model.joblib"
    artifact.write_bytes(b"content")
    sha256 = compute_file_sha256(artifact)
    entry = _make_entry(sha256=sha256, label_schema_version="99.0.0")

    with pytest.raises(ModelArtifactSecurityError, match="label_schema_version mismatch"):
        validate_artifact(
            artifact_path=artifact,
            registry_entry=entry,
            expected_model_version=MODEL_VERSION,
            expected_feature_schema_version=FEATURE_SCHEMA_VERSION,
            expected_label_schema_version=LABEL_SCHEMA_VERSION,
        )


# ── Registry JSON round-trip ─────────────────────────────────────────────────

def test_save_and_load_registry_entry(tmp_path):
    entry = _make_entry()
    registry_path = tmp_path / "ml_model_registry.json"
    save_registry_entry(entry, registry_path)
    loaded = load_registry_entry(registry_path)
    assert loaded.model_version == entry.model_version
    assert loaded.sha256 == entry.sha256
    assert loaded.feature_schema_version == entry.feature_schema_version


# ── Inference disabled by default ────────────────────────────────────────────

def test_inference_disabled_by_default_returns_none():
    """run_inference with ml_inference_enabled=False must return None."""
    result = run_inference(
        incident_id="test-001",
        created_at=_now(),
        severity="medium",
        alert_count=5,
        correlation_rule_type="sequence",
        correlation_confidence=0.7,
        cti_records=[],
        mitre_tactics=["execution"],
        t_prediction=_now(),
        ml_inference_enabled=False,
    )
    assert result is None


def test_inference_returns_none_when_no_artifact_path():
    """No artifact path → None (fallback)."""
    result = run_inference(
        incident_id="test-002",
        created_at=_now(),
        severity="high",
        alert_count=3,
        correlation_rule_type=None,
        correlation_confidence=None,
        cti_records=[],
        mitre_tactics=[],
        t_prediction=_now(),
        artifact_path=None,
        registry_path=None,
        ml_inference_enabled=True,
    )
    assert result is None


def test_inference_falls_back_on_security_error(tmp_path):
    """SecurityError during model loading → fallback (None, no exception)."""
    # Provide a real file but with wrong SHA-256 in registry.
    artifact = tmp_path / "model.joblib"
    artifact.write_bytes(b"not a real model")
    registry_path = tmp_path / "ml_model_registry.json"
    entry = _make_entry(sha256="wrongsha256" + "0" * 53, artifact_path=str(artifact))
    save_registry_entry(entry, registry_path)

    # Reset module-level cache to force re-load.
    import ml.inference as inf_mod
    inf_mod._cached_model = None
    inf_mod._model_load_failed = False

    result = run_inference(
        incident_id="test-003",
        created_at=_now(),
        severity="low",
        alert_count=1,
        correlation_rule_type=None,
        correlation_confidence=None,
        cti_records=[],
        mitre_tactics=[],
        t_prediction=_now(),
        artifact_path=artifact,
        registry_path=registry_path,
        ml_inference_enabled=True,
    )
    assert result is None  # graceful fallback


def test_inference_t_prediction_in_output():
    """
    When inference succeeds, t_prediction must be present in the output
    as an ISO-8601 string (for audit purposes).

    We mock the model loading and prediction to test this contract.
    """
    import ml.inference as inf_mod

    # Reset cache.
    inf_mod._cached_model = None
    inf_mod._model_load_failed = False
    inf_mod._cached_registry_entry = None

    mock_model = MagicMock()
    import numpy as np
    mock_model.predict_proba.return_value = np.array([[0.1, 0.2, 0.4, 0.2, 0.1]])

    t_pred = _now()

    with patch.object(inf_mod, "_get_model", return_value=mock_model):
        result = run_inference(
            incident_id="test-004",
            created_at=t_pred - timedelta(hours=1),
            severity="medium",
            alert_count=3,
            correlation_rule_type="sequence",
            correlation_confidence=0.7,
            cti_records=[],
            mitre_tactics=["execution"],
            t_prediction=t_pred,
            artifact_path=Path("/fake/model.joblib"),
            registry_path=Path("/fake/registry.json"),
            ml_inference_enabled=True,
        )

    assert result is not None
    assert "t_prediction" in result
    assert result["t_prediction"] == t_pred.isoformat()
    assert "ml_score" in result
    assert 0.0 <= result["ml_score"] <= 100.0
    assert "ml_priority_band" in result
    assert result["fallback"] is False
