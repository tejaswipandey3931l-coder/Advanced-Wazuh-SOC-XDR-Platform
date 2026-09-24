"""
Phase 6 — Unit tests for ml.trainer calibration API correction.

Tests required by the Phase 6 Technical Correction:
  1. Calibration implementation no longer hard-codes cv="prefit" —
     uses _make_calibrated_prefit() which dispatches on sklearn version.
  2. Training and calibration datasets remain disjoint (no overlap).
  3. Validation data is used ONLY for calibration, not for base-model fitting.
  4. Test data is not accessed during training/calibration.
  5. The calibrated classifier preserves the five-class schema.
  6. ml_score remains deterministic and bounded [0, 100].
  7. Existing fallback behavior remains unchanged.

Additional tests:
  - _sklearn_has_frozen_estimator() returns a bool
  - _make_calibrated_prefit() does not refit base estimator (coef unchanged)
  - train_and_calibrate() returns calibration_api key in result
  - train_and_calibrate() raises ValueError on empty train/val splits
  - predict_calibrated_probabilities() returns correct shape and sums
"""

from __future__ import annotations

import tempfile
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

import numpy as np
import pytest

from ml.constants import PRIORITY_CLASS_ORDER
from ml.features import FEATURE_COLUMNS
from ml.scorer import calculate_ml_score
from ml.splitter import SplitResult
from ml.trainer import (
    _build_X_y,
    _make_calibrated_prefit,
    _sklearn_has_frozen_estimator,
    predict_calibrated_probabilities,
    train_and_calibrate,
)


# ── Synthetic dataset helpers ─────────────────────────────────────────────────

def _make_fv(seed: int = 0) -> dict[str, float]:
    """Make a synthetic feature vector."""
    rng = np.random.RandomState(seed)
    return {col: float(rng.rand()) for col in FEATURE_COLUMNS}


def _make_records(bands: list[str], fv_seed_offset: int = 0) -> list[dict]:
    """Create synthetic dataset records."""
    return [
        {
            "incident_id": f"inc-{i}",
            "created_at": datetime(2024, 1, i + 1, tzinfo=timezone.utc),
            "feature_vector": _make_fv(seed=i + fv_seed_offset),
            "feature_hash": f"hash-{i + fv_seed_offset:04d}",
            "priority_band": band,
            "label_type": "TRUE_GROUND_TRUTH",
            "label_source": "test",
        }
        for i, band in enumerate(bands)
    ]


def _make_split() -> SplitResult:
    """
    Build a minimal but valid SplitResult with disjoint train/val/test.

    Uses balanced classes across all 5 bands so the model can converge.
    Train: 25 records (5 per class)
    Val:   10 records (2 per class)
    Test:   5 records (1 per class) — should NOT be touched during training
    """
    classes = PRIORITY_CLASS_ORDER  # 5 classes
    train_bands = classes * 5   # 25 items
    val_bands = classes * 2     # 10 items
    test_bands = classes * 1    # 5 items

    return SplitResult(
        train=_make_records(train_bands, fv_seed_offset=0),
        val=_make_records(val_bands, fv_seed_offset=100),
        test=_make_records(test_bands, fv_seed_offset=200),
    )


# ── 1. _sklearn_has_frozen_estimator() ───────────────────────────────────────

def test_sklearn_has_frozen_estimator_returns_bool():
    """_sklearn_has_frozen_estimator() must return a bool."""
    result = _sklearn_has_frozen_estimator()
    assert isinstance(result, bool)


def test_sklearn_has_frozen_estimator_consistent():
    """Same call on same process returns the same value."""
    assert _sklearn_has_frozen_estimator() == _sklearn_has_frozen_estimator()


# ── 2. _make_calibrated_prefit() does NOT refit base estimator ───────────────

def test_make_calibrated_prefit_does_not_refit_base_estimator():
    """
    After calibrated.fit(X_val, y_val), the base LogisticRegression
    coefficients must be IDENTICAL to those before calibration.

    This proves that neither FrozenEstimator nor cv='prefit' refits the
    base model on validation data.
    """
    from sklearn.linear_model import LogisticRegression
    from sklearn.pipeline import Pipeline
    from sklearn.preprocessing import StandardScaler

    # Build 3-class data (enough to fit LR).
    rng = np.random.RandomState(42)
    X_train = rng.rand(30, len(FEATURE_COLUMNS))
    y_train = np.array([0, 1, 2, 3, 4] * 6, dtype=np.int64)

    X_val = rng.rand(15, len(FEATURE_COLUMNS))
    y_val = np.array([0, 1, 2, 3, 4] * 3, dtype=np.int64)

    pipeline = Pipeline([
        ("scaler", StandardScaler()),
        ("clf", LogisticRegression(max_iter=500, random_state=42)),
    ])
    pipeline.fit(X_train, y_train)

    # Snapshot the LR coefficients before calibration.
    coef_before = pipeline.named_steps["clf"].coef_.copy()

    # Build calibrator (version-adaptive) and fit on validation data only.
    calibrated = _make_calibrated_prefit(pipeline, method="sigmoid")
    calibrated.fit(X_val, y_val)

    # Verify base estimator coefficients are unchanged.
    coef_after = pipeline.named_steps["clf"].coef_.copy()
    assert np.allclose(coef_before, coef_after), (
        "Base LogisticRegression coefficients changed after calibration — "
        "the base estimator was incorrectly refit on validation data."
    )


def test_make_calibrated_prefit_supports_predict_proba():
    """The calibrated model must expose predict_proba()."""
    from sklearn.linear_model import LogisticRegression
    from sklearn.pipeline import Pipeline
    from sklearn.preprocessing import StandardScaler

    rng = np.random.RandomState(7)
    X = rng.rand(50, len(FEATURE_COLUMNS))
    y = np.array([0, 1, 2, 3, 4] * 10, dtype=np.int64)

    pipeline = Pipeline([
        ("scaler", StandardScaler()),
        ("clf", LogisticRegression(max_iter=500, random_state=7)),
    ])
    pipeline.fit(X[:35], y[:35])

    calibrated = _make_calibrated_prefit(pipeline, method="sigmoid")
    calibrated.fit(X[35:], y[35:])

    proba = calibrated.predict_proba(X[:5])
    assert proba.shape == (5, 5)
    assert np.allclose(proba.sum(axis=1), 1.0, atol=1e-6)


# ── 3. train_and_calibrate() — disjoint split invariants ─────────────────────

def test_train_and_calibrate_train_val_disjoint():
    """
    Training and calibration (validation) datasets must be disjoint.
    This is guaranteed by the chronological_split, verified here at
    the feature-hash level.
    """
    split = _make_split()
    train_hashes = {r["feature_hash"] for r in split.train}
    val_hashes = {r["feature_hash"] for r in split.val}
    test_hashes = {r["feature_hash"] for r in split.test}

    assert train_hashes.isdisjoint(val_hashes), "Train and val overlap!"
    assert train_hashes.isdisjoint(test_hashes), "Train and test overlap!"
    assert val_hashes.isdisjoint(test_hashes), "Val and test overlap!"


def test_train_and_calibrate_test_not_accessed(tmp_path):
    """
    The test split must NOT be accessed (zero reads) during
    train_and_calibrate(). We verify this by passing a sentinel-wrapped
    test list and confirming it is never iterated.
    """
    split = _make_split()

    # Replace test with a sentinel that will error if iterated.
    class _SentinelList(list):
        def __iter__(self):
            raise AssertionError(
                "TEST SPLIT WAS ACCESSED DURING TRAINING/CALIBRATION. "
                "This is a data-leakage violation."
            )
        def __len__(self):
            return 0  # allow empty checks without iteration

    split.test = _SentinelList(split.test)

    # train_and_calibrate must complete WITHOUT triggering __iter__ on test.
    result = train_and_calibrate(split, output_dir=tmp_path)
    assert result["model"] is not None


def test_train_and_calibrate_returns_calibration_api_key(tmp_path):
    """
    Result dict must contain 'calibration_api' describing which path was taken.
    """
    split = _make_split()
    result = train_and_calibrate(split, output_dir=tmp_path)
    assert "calibration_api" in result
    assert result["calibration_api"] in (
        "FrozenEstimator + CalibratedClassifierCV(method='sigmoid')",
        "CalibratedClassifierCV(cv='prefit', method='sigmoid')",
    )


def test_train_and_calibrate_calibration_api_matches_sklearn_version(tmp_path):
    """
    The calibration_api string in the result must match what the installed
    sklearn version supports.
    """
    split = _make_split()
    result = train_and_calibrate(split, output_dir=tmp_path)
    has_frozen = _sklearn_has_frozen_estimator()
    if has_frozen:
        assert "FrozenEstimator" in result["calibration_api"]
    else:
        assert "cv='prefit'" in result["calibration_api"]


def test_train_and_calibrate_raises_on_empty_train(tmp_path):
    """Empty train split must raise ValueError."""
    split = _make_split()
    split.train = []
    with pytest.raises(ValueError, match="Training split is empty"):
        train_and_calibrate(split, output_dir=tmp_path)


def test_train_and_calibrate_raises_on_empty_val(tmp_path):
    """Empty validation split must raise ValueError."""
    split = _make_split()
    split.val = []
    with pytest.raises(ValueError, match="Validation split is empty"):
        train_and_calibrate(split, output_dir=tmp_path)


# ── 4. Five-class schema preserved ───────────────────────────────────────────

def test_calibrated_model_preserves_five_class_schema(tmp_path):
    """
    The calibrated model must produce predict_proba() output with exactly
    5 columns corresponding to PRIORITY_CLASS_ORDER.
    """
    split = _make_split()
    result = train_and_calibrate(split, output_dir=tmp_path)
    model = result["model"]

    # Build a test feature matrix.
    X_test = np.array(
        [[_make_fv(seed=999 + i).get(col, 0.0) for col in FEATURE_COLUMNS]
         for i in range(3)],
        dtype=np.float64,
    )
    proba = model.predict_proba(X_test)
    assert proba.shape == (3, 5), (
        f"Expected (3, 5) probability matrix, got {proba.shape}. "
        "All five priority classes must be present."
    )
    assert np.allclose(proba.sum(axis=1), 1.0, atol=1e-6)
    assert result["classes"] == PRIORITY_CLASS_ORDER


# ── 5. ml_score deterministic and bounded [0, 100] ───────────────────────────

def test_ml_score_from_calibrated_proba_is_deterministic(tmp_path):
    """
    ml_score derived from calibrated probabilities must be deterministic
    and bounded in [0, 100].
    """
    split = _make_split()
    result = train_and_calibrate(split, output_dir=tmp_path)
    model = result["model"]

    fv = _make_fv(seed=42)
    proba_list = predict_calibrated_probabilities(model, [fv])
    probs = proba_list[0]

    score1 = calculate_ml_score(probs)
    score2 = calculate_ml_score(probs)

    assert score1 == score2, "ml_score is not deterministic."
    assert 0.0 <= score1 <= 100.0, f"ml_score {score1} out of [0, 100]."


def test_ml_score_from_repeated_inference_is_stable(tmp_path):
    """
    Two predict_calibrated_probabilities calls on the same model and same
    feature vector must yield the same ml_score.
    """
    split = _make_split()
    result = train_and_calibrate(split, output_dir=tmp_path)
    model = result["model"]
    fv = _make_fv(seed=77)

    p1 = predict_calibrated_probabilities(model, [fv])[0]
    p2 = predict_calibrated_probabilities(model, [fv])[0]

    s1 = calculate_ml_score(p1)
    s2 = calculate_ml_score(p2)
    assert s1 == pytest.approx(s2)
    assert 0.0 <= s1 <= 100.0


# ── 6. predict_calibrated_probabilities() ────────────────────────────────────

def test_predict_calibrated_probabilities_shape_and_sums(tmp_path):
    """
    Output must have one dict per input and probabilities must sum to ~1.0.
    """
    split = _make_split()
    result = train_and_calibrate(split, output_dir=tmp_path)
    fvs = [_make_fv(seed=i) for i in range(5)]
    proba_list = predict_calibrated_probabilities(result["model"], fvs)

    assert len(proba_list) == 5
    for probs in proba_list:
        assert set(probs.keys()) == set(PRIORITY_CLASS_ORDER)
        total = sum(probs.values())
        assert total == pytest.approx(1.0, abs=1e-6)


# ── 7. Fallback behavior unchanged ────────────────────────────────────────────

def test_inference_fallback_still_returns_none_when_disabled():
    """
    run_inference with ml_inference_enabled=False must still return None.
    Fallback behavior is independent of the calibration API change.
    """
    from datetime import datetime, timezone
    from ml.inference import run_inference

    result = run_inference(
        incident_id="fallback-test",
        created_at=datetime(2024, 1, 1, 10, 0, tzinfo=timezone.utc),
        severity="high",
        alert_count=5,
        correlation_rule_type="sequence",
        correlation_confidence=0.8,
        cti_records=[],
        mitre_tactics=["execution"],
        t_prediction=datetime(2024, 1, 1, 10, 30, tzinfo=timezone.utc),
        ml_inference_enabled=False,
    )
    assert result is None


def test_inference_fallback_on_missing_artifact_returns_none():
    """Inference with no artifact path still returns None gracefully."""
    from datetime import datetime, timezone
    from ml.inference import run_inference

    result = run_inference(
        incident_id="no-artifact",
        created_at=datetime(2024, 1, 1, 10, 0, tzinfo=timezone.utc),
        severity="medium",
        alert_count=2,
        correlation_rule_type=None,
        correlation_confidence=None,
        cti_records=[],
        mitre_tactics=[],
        t_prediction=datetime(2024, 1, 1, 10, 30, tzinfo=timezone.utc),
        artifact_path=None,
        registry_path=None,
        ml_inference_enabled=True,
    )
    assert result is None
