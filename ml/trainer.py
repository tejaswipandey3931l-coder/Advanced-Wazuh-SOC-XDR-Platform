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

    The test split is NEVER touched during this function.

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

    Raises
    ------
    ValueError
        If train or val splits are empty.
    RuntimeError
        If scikit-learn is not installed.
    """
    try:
        import joblib
        from sklearn.calibration import CalibratedClassifierCV
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

    # ── Base estimator ────────────────────────────────────────────────────────
    # LogisticRegression: interpretable, fast, suitable for research baseline.
    # max_iter=2000 to ensure convergence on small datasets.
    base_clf = LogisticRegression(
        multi_class="multinomial",
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

    # ── Train on training split ───────────────────────────────────────────────
    pipeline.fit(X_train, y_train)

    # ── Calibrate on validation split ONLY ───────────────────────────────────
    # CalibratedClassifierCV(cv="prefit") uses an already-fitted estimator.
    calibrated = CalibratedClassifierCV(
        estimator=pipeline,
        method="sigmoid",   # Platt scaling
        cv="prefit",
    )
    calibrated.fit(X_val, y_val)

    # ── Accuracy on train / val ───────────────────────────────────────────────
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
    import sklearn
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
        notes="Logistic Regression + Platt scaling (validation only)",
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
