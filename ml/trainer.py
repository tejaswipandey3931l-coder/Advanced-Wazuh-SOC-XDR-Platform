"""
Phase 6 — Model training and calibration.

Design constraints
------------------
* Model type: scikit-learn classifier (LogisticRegression default).
  No deep neural networks, no online learning, no reinforcement learning.
* Calibration: Platt scaling (CalibratedClassifierCV with method="sigmoid")
  using the VALIDATION split ONLY.  The test set is NEVER used during
  calibration.
* Primary task: 5-class multiclass classification:
    INFORMATIONAL, LOW, MEDIUM, HIGH, CRITICAL
* The trained + calibrated model exposes predict_proba() which returns
  calibrated class probabilities — these are fed directly to
  ml.scorer.calculate_ml_score().
* risk-v1 values are NEVER used as features.

Calibration API
---------------
scikit-learn 1.6+ deprecates CalibratedClassifierCV(cv="prefit") in favour
of wrapping the already-fitted estimator with FrozenEstimator:

    from sklearn.frozen import FrozenEstimator
    frozen = FrozenEstimator(fitted_pipeline)
    calibrated = CalibratedClassifierCV(frozen, method="sigmoid")
    calibrated.fit(X_val, y_val)

sklearn 1.5.x does not yet ship sklearn.frozen; the equivalent is
CalibratedClassifierCV(fitted_pipeline, cv="prefit", method="sigmoid").

Both paths guarantee IDENTICAL semantics:
    - LogisticRegression (and the whole Pipeline) is fitted ONLY on X_train.
    - The calibration scalers are fitted ONLY on X_val.
    - X_test is NEVER passed to .fit() at any stage.

_make_calibrated_prefit() detects the installed version at runtime and
selects the appropriate path automatically, future-proofing the code
without breaking the current environment.

Artifact output
---------------
After training, the pipeline saves a joblib artifact and writes a
registry JSON entry (see ml.registry).  Both files are research-only
and are NOT production database records.
"""

from __future__ import annotations

import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import numpy as np

from .constants import (
    FEATURE_SCHEMA_VERSION,
    LABEL_SCHEMA_VERSION,
    MODEL_VERSION,
    PRIORITY_CLASS_ORDER,
)
from .features import FEATURE_COLUMNS
from .registry import (
    ModelRegistryEntry,
    compute_file_sha256,
    save_registry_entry,
)
from .splitter import SplitResult


def _sklearn_has_frozen_estimator() -> bool:
    """
    Return True if sklearn.frozen.FrozenEstimator is available (sklearn ≥1.6).
    Returns False on sklearn 1.5.x where the module does not yet exist.
    """
    try:
        from sklearn.frozen import FrozenEstimator  # noqa: F401
        return True
    except ImportError:
        return False


def _make_calibrated_prefit(fitted_estimator: Any, method: str = "sigmoid") -> Any:
    """
    Build a CalibratedClassifierCV wrapper around an ALREADY-FITTED estimator
    using the API that is appropriate for the installed scikit-learn version.

    sklearn ≥1.6 (FrozenEstimator available):
        frozen = FrozenEstimator(fitted_estimator)
        calibrated = CalibratedClassifierCV(frozen, method=method)
        # caller must call calibrated.fit(X_val, y_val) — LR NOT refit

    sklearn 1.5.x (FrozenEstimator not yet available):
        calibrated = CalibratedClassifierCV(
            fitted_estimator, cv="prefit", method=method
        )
        # caller must call calibrated.fit(X_val, y_val) — LR NOT refit

    Both paths provide IDENTICAL guarantees:
        1. The base estimator (LogisticRegression + Pipeline) is NEVER
           refit when calibrated.fit(X_val, y_val) is called.
        2. Only the sigmoid calibration scalers are fitted on X_val.
        3. X_test is never passed to .fit() at any stage.

    Parameters
    ----------
    fitted_estimator:
        An already-fitted sklearn Pipeline (or estimator) that exposes
        predict_proba() and classes_.
    method:
        Calibration method: "sigmoid" (Platt) or "isotonic".

    Returns
    -------
    An unfitted CalibratedClassifierCV ready for .fit(X_val, y_val).
    """
    from sklearn.calibration import CalibratedClassifierCV  # noqa: PLC0415

    if _sklearn_has_frozen_estimator():
        from sklearn.frozen import FrozenEstimator  # noqa: PLC0415
        # sklearn ≥1.6: wrap with FrozenEstimator to prevent any accidental
        # refitting of the base estimator.
        frozen = FrozenEstimator(fitted_estimator)
        return CalibratedClassifierCV(frozen, method=method)
    else:
        # sklearn 1.5.x: cv="prefit" provides the same guarantee —
        # it uses the estimator as-is and does NOT call estimator.fit()
        # during CalibratedClassifierCV.fit().
        return CalibratedClassifierCV(
            fitted_estimator,
            cv="prefit",
            method=method,
        )


def _build_X_y(
    records: list[dict],
) -> tuple[np.ndarray, np.ndarray]:
    """
    Convert a list of dataset records to numpy arrays X, y.

    Parameters
    ----------
    records:
        Each dict must contain ``feature_vector`` (dict[str, float]) and
        ``priority_band`` (str).

    Returns
    -------
    X: ndarray shape (n_samples, n_features)
    y: ndarray shape (n_samples,) — integer class indices
    """
    class_to_idx = {cls: i for i, cls in enumerate(PRIORITY_CLASS_ORDER)}
    X_rows = [
        [r["feature_vector"].get(col, 0.0) for col in FEATURE_COLUMNS]
        for r in records
    ]
    y_rows = [class_to_idx[r["priority_band"]] for r in records]
    return np.array(X_rows, dtype=np.float64), np.array(y_rows, dtype=np.int64)


def train_and_calibrate(
    split: SplitResult,
    output_dir: Path,
) -> dict[str, Any]:
    """
    Train a scikit-learn classifier on the training split and calibrate it
    using the validation split.

    Data isolation guarantees
    -------------------------
    1. X_train / y_train  → LogisticRegression (+ Pipeline) is fit HERE ONLY.
    2. X_val / y_val      → Calibration scalers are fit HERE ONLY.
    3. X_test / y_test    → NEVER passed to .fit() inside this function.

    The test split in ``split`` is accessed ZERO times during this function.

    Parameters
    ----------
    split:
        Output of ml.splitter.chronological_split().  Must have non-empty
        train and val lists.
    output_dir:
        Directory where the joblib artifact and registry JSON are saved.

    Returns
    -------
    dict with keys:
        - ``model``: calibrated sklearn estimator
        - ``artifact_path``: Path to the saved joblib file
        - ``registry_entry``: ModelRegistryEntry
        - ``train_accuracy``: float
        - ``val_accuracy``: float
        - ``classes``: list[str]   # PRIORITY_CLASS_ORDER
        - ``calibration_api``: str  # which path was taken

    Raises
    ------
    ValueError
        If train or val splits are empty.
    RuntimeError
        If scikit-learn is not installed.
    """
    try:
        import joblib
        import sklearn
        from sklearn.linear_model import LogisticRegression
        from sklearn.metrics import accuracy_score
        from sklearn.preprocessing import StandardScaler
        from sklearn.pipeline import Pipeline
    except ImportError as exc:
        raise RuntimeError(
            "scikit-learn and joblib are required for model training. "
            f"Install them with: pip install scikit-learn joblib. "
            f"Original error: {exc}"
        ) from exc

    if not split.train:
        raise ValueError("Training split is empty; cannot train model.")
    if not split.val:
        raise ValueError(
            "Validation split is empty; cannot calibrate model. "
            "Increase the dataset size or adjust split fractions."
        )

    X_train, y_train = _build_X_y(split.train)
    X_val, y_val = _build_X_y(split.val)
    # NOTE: split.test is intentionally NOT unpacked here.
    #       Test data is never accessed during training or calibration.

    # ── Base estimator ────────────────────────────────────────────────────────
    # LogisticRegression: interpretable, fast, suitable for research baseline.
    # max_iter=2000 to ensure convergence on small datasets.
    base_clf = LogisticRegression(
        solver="lbfgs",
        max_iter=2000,
        C=1.0,
        random_state=42,
        class_weight="balanced",
    )

    # Wrap in a StandardScaler pipeline so features are normalised.
    pipeline = Pipeline([
        ("scaler", StandardScaler()),
        ("clf", base_clf),
    ])

    # ── Step 1: Fit base pipeline on training split ONLY ─────────────────────
    pipeline.fit(X_train, y_train)

    # ── Step 2: Calibrate on validation split ONLY ───────────────────────────
    # _make_calibrated_prefit() selects the version-appropriate API:
    #   sklearn ≥1.6 → FrozenEstimator (base pipeline frozen, not refit)
    #   sklearn 1.5.x → cv="prefit"   (same guarantee, different API)
    calibrated = _make_calibrated_prefit(pipeline, method="sigmoid")
    # This call fits ONLY the sigmoid calibration scalers on X_val.
    # It does NOT refit the LogisticRegression or StandardScaler.
    calibrated.fit(X_val, y_val)

    # Record which API path was taken for auditability.
    calibration_api = (
        "FrozenEstimator + CalibratedClassifierCV(method='sigmoid')"
        if _sklearn_has_frozen_estimator()
        else "CalibratedClassifierCV(cv='prefit', method='sigmoid')"
    )

    # ── Accuracy on train / val (test set is NOT used here) ──────────────────
    train_preds = calibrated.predict(X_train)
    val_preds = calibrated.predict(X_val)
    train_acc = float(accuracy_score(y_train, train_preds))
    val_acc = float(accuracy_score(y_val, val_preds))

    # ── Save artifact ─────────────────────────────────────────────────────────
    output_dir.mkdir(parents=True, exist_ok=True)
    artifact_filename = f"ml_model_{MODEL_VERSION}.joblib"
    artifact_path = output_dir / artifact_filename
    joblib.dump(calibrated, artifact_path)

    # ── Build registry entry ──────────────────────────────────────────────────
    sha256 = compute_file_sha256(artifact_path)
    py_ver = f"{sys.version_info.major}.{sys.version_info.minor}"
    registry_entry = ModelRegistryEntry(
        model_version=MODEL_VERSION,
        feature_schema_version=FEATURE_SCHEMA_VERSION,
        label_schema_version=LABEL_SCHEMA_VERSION,
        sha256=sha256,
        python_version=py_ver,
        library_versions={
            "scikit-learn": sklearn.__version__,
            "numpy": np.__version__,
            "joblib": joblib.__version__,
        },
        trained_at_utc=datetime.now(timezone.utc).isoformat(),
        artifact_path=str(artifact_path),
        notes=(
            f"LogisticRegression + Platt scaling (validation only). "
            f"Calibration API: {calibration_api}."
        ),
    )
    registry_path = output_dir / "ml_model_registry.json"
    save_registry_entry(registry_entry, registry_path)

    return {
        "model": calibrated,
        "artifact_path": artifact_path,
        "registry_entry": registry_entry,
        "train_accuracy": train_acc,
        "val_accuracy": val_acc,
        "classes": PRIORITY_CLASS_ORDER,
        "calibration_api": calibration_api,
    }


def predict_calibrated_probabilities(
    model: Any,
    feature_dicts: list[dict[str, float]],
) -> list[dict[str, float]]:
    """
    Run inference with the calibrated model to produce per-class probabilities.

    Parameters
    ----------
    model:
        The calibrated sklearn estimator from train_and_calibrate().
    feature_dicts:
        List of feature vectors (dicts keyed by FEATURE_COLUMNS).

    Returns
    -------
    List of dicts mapping class_name → probability for each incident.
    Each dict sums to ~1.0.
    """
    X = np.array(
        [[fv.get(col, 0.0) for col in FEATURE_COLUMNS] for fv in feature_dicts],
        dtype=np.float64,
    )
    proba_matrix = model.predict_proba(X)  # shape (n_samples, n_classes)

    results = []
    for row in proba_matrix:
        prob_dict = {cls: float(row[i]) for i, cls in enumerate(PRIORITY_CLASS_ORDER)}
        results.append(prob_dict)
    return results
