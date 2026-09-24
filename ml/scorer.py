"""
Phase 6 — Deterministic ml_score calculation.

This module provides the ONLY authoritative definition of ml_score.

Contract
--------
ml_score is derived from calibrated class probabilities using a
deterministic ordinal expected-value formula:

    ml_score = Σ P(class_i) × class_weight_i

where:
    class_weight_i ∈ {INFORMATIONAL=0, LOW=25, MEDIUM=50, HIGH=75, CRITICAL=100}

Properties guaranteed:
    1. ml_score ∈ [0.0, 100.0]
    2. ml_score is independent of risk-v1 score.
    3. risk-v1 score is NEVER used as input.
    4. Calibrated class probabilities remain accessible separately.
    5. Permutation of equivalent inputs produces the same score.
    6. All probability mass on INFORMATIONAL → 0.0
    7. All probability mass on CRITICAL → 100.0
    8. Equal probabilities (1/5 each) → 50.0 (expected mid-point)
"""

from __future__ import annotations

from .constants import CLASS_ORDINAL_WEIGHTS, ML_PRIORITY_THRESHOLDS, MLPriorityBand, PRIORITY_CLASS_ORDER


def calculate_ml_score(calibrated_probabilities: dict[str, float]) -> float:
    """
    Convert calibrated class probabilities to a scalar ml_score ∈ [0.0, 100.0].

    Parameters
    ----------
    calibrated_probabilities:
        A mapping of class_name → probability, where class names are the
        uppercase priority band literals (e.g., ``"INFORMATIONAL"``, ...,
        ``"CRITICAL"``).  Probabilities must sum to 1.0 (within 1e-6).
        Any class absent from the dict is treated as probability 0.0.

    Returns
    -------
    float
        Scalar score in [0.0, 100.0].

    Raises
    ------
    ValueError
        If any class name is unrecognised or probabilities are negative.
    """
    for cls, prob in calibrated_probabilities.items():
        if cls not in CLASS_ORDINAL_WEIGHTS:
            raise ValueError(
                f"Unrecognised class name {cls!r}. "
                f"Expected one of {list(CLASS_ORDINAL_WEIGHTS.keys())}."
            )
        if prob < 0.0:
            raise ValueError(
                f"Probability for class {cls!r} is negative: {prob!r}."
            )

    # Compute score using deterministic ordinal expected-value mapping.
    score = 0.0
    for cls, weight in CLASS_ORDINAL_WEIGHTS.items():
        p = calibrated_probabilities.get(cls, 0.0)
        score += p * weight

    # Clamp to [0, 100] to guard against floating-point drift.
    return max(0.0, min(100.0, score))


def map_ml_priority_band(ml_score: float) -> MLPriorityBand:
    """
    Map ml_score ∈ [0.0, 100.0] to an MLPriorityBand using the same five
    thresholds as risk-v1 PriorityBand.

    Brackets:
      [0.00, 20.00)  → INFORMATIONAL
      [20.00, 40.00) → LOW
      [40.00, 60.00) → MEDIUM
      [60.00, 80.00) → HIGH
      [80.00, 100.00] → CRITICAL
    """
    clamped = max(0.0, min(100.0, float(ml_score)))
    for threshold, band_name in ML_PRIORITY_THRESHOLDS:
        if clamped < threshold:
            return MLPriorityBand(band_name)
    return MLPriorityBand.CRITICAL


def uniform_ml_score() -> float:
    """
    Return the ml_score when all 5 classes have equal probability (0.2 each).

    Equal distribution → ordinal midpoint:
        0.2*0 + 0.2*25 + 0.2*50 + 0.2*75 + 0.2*100 = 50.0
    """
    equal_probs = {cls: 0.2 for cls in PRIORITY_CLASS_ORDER}
    return calculate_ml_score(equal_probs)
