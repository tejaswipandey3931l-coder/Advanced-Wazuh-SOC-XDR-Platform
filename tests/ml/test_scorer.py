"""
Phase 6 — Unit tests for ml.scorer.

Tests
-----
- Probabilities summing to 1 produce deterministic scores
- All probability mass on INFORMATIONAL → 0.0
- All probability mass on CRITICAL → 100.0
- Equal probabilities → 50.0
- Score remains within [0.0, 100.0]
- Permutation/order of equivalent probability inputs does not alter result
- ML priority band mapping (same thresholds as risk-v1)
- Negative probability → ValueError
- Unknown class name → ValueError
- Independent of risk-v1 (no risk-v1 imports required)
"""

from __future__ import annotations

import pytest

from ml.scorer import calculate_ml_score, map_ml_priority_band, uniform_ml_score
from ml.constants import MLPriorityBand, PRIORITY_CLASS_ORDER


# ── Helper ────────────────────────────────────────────────────────────────────

def _all_on(cls: str) -> dict[str, float]:
    """All probability mass on a single class."""
    return {c: (1.0 if c == cls else 0.0) for c in PRIORITY_CLASS_ORDER}


def _uniform() -> dict[str, float]:
    """Equal probability across all 5 classes."""
    return {c: 0.2 for c in PRIORITY_CLASS_ORDER}


# ── Deterministic score tests ─────────────────────────────────────────────────

def test_all_mass_informational_gives_zero():
    """All probability mass on INFORMATIONAL → ml_score == 0.0."""
    score = calculate_ml_score(_all_on("INFORMATIONAL"))
    assert score == pytest.approx(0.0)


def test_all_mass_low_gives_25():
    """All probability mass on LOW → ml_score == 25.0."""
    score = calculate_ml_score(_all_on("LOW"))
    assert score == pytest.approx(25.0)


def test_all_mass_medium_gives_50():
    """All probability mass on MEDIUM → ml_score == 50.0."""
    score = calculate_ml_score(_all_on("MEDIUM"))
    assert score == pytest.approx(50.0)


def test_all_mass_high_gives_75():
    """All probability mass on HIGH → ml_score == 75.0."""
    score = calculate_ml_score(_all_on("HIGH"))
    assert score == pytest.approx(75.0)


def test_all_mass_critical_gives_100():
    """All probability mass on CRITICAL → ml_score == 100.0."""
    score = calculate_ml_score(_all_on("CRITICAL"))
    assert score == pytest.approx(100.0)


def test_equal_probabilities_give_50():
    """Equal probabilities (0.2 each) → ml_score == 50.0."""
    score = calculate_ml_score(_uniform())
    assert score == pytest.approx(50.0)


def test_uniform_helper_gives_50():
    """uniform_ml_score() convenience helper also returns 50.0."""
    assert uniform_ml_score() == pytest.approx(50.0)


def test_score_bounded_between_0_and_100():
    """Any valid probability input must produce a score in [0, 100]."""
    probs = {"INFORMATIONAL": 0.1, "LOW": 0.2, "MEDIUM": 0.3, "HIGH": 0.2, "CRITICAL": 0.2}
    score = calculate_ml_score(probs)
    assert 0.0 <= score <= 100.0


def test_deterministic_repeated_calls():
    """Same input → same output on repeated calls."""
    probs = {"INFORMATIONAL": 0.05, "LOW": 0.10, "MEDIUM": 0.45, "HIGH": 0.30, "CRITICAL": 0.10}
    s1 = calculate_ml_score(probs)
    s2 = calculate_ml_score(probs)
    assert s1 == s2


def test_score_independent_of_input_dict_ordering():
    """
    Python dicts preserve insertion order, but the formula must be
    independent of which order keys appear in the dict.
    """
    probs_a = {
        "INFORMATIONAL": 0.1, "LOW": 0.2, "MEDIUM": 0.3,
        "HIGH": 0.2, "CRITICAL": 0.2,
    }
    probs_b = {
        "CRITICAL": 0.2, "HIGH": 0.2, "MEDIUM": 0.3,
        "LOW": 0.2, "INFORMATIONAL": 0.1,
    }
    assert calculate_ml_score(probs_a) == pytest.approx(calculate_ml_score(probs_b))


def test_missing_class_treated_as_zero():
    """Absent classes are treated as probability 0.0."""
    # Only CRITICAL = 1.0, rest missing.
    score = calculate_ml_score({"CRITICAL": 1.0})
    assert score == pytest.approx(100.0)


def test_partial_probabilities_score_correctly():
    """Partial probability mix: 50% HIGH + 50% MEDIUM → 62.5."""
    probs = {"MEDIUM": 0.5, "HIGH": 0.5}
    expected = 0.5 * 50.0 + 0.5 * 75.0  # = 62.5
    assert calculate_ml_score(probs) == pytest.approx(expected)


# ── Input validation tests ────────────────────────────────────────────────────

def test_negative_probability_raises_value_error():
    """Negative probability must raise ValueError."""
    with pytest.raises(ValueError, match="negative"):
        calculate_ml_score({"INFORMATIONAL": -0.1, "CRITICAL": 1.1})


def test_unknown_class_name_raises_value_error():
    """Unrecognised class name must raise ValueError."""
    with pytest.raises(ValueError, match="Unrecognised class name"):
        calculate_ml_score({"risk_score": 0.5})


# ── ML priority band mapping ──────────────────────────────────────────────────

def test_ml_band_informational():
    assert map_ml_priority_band(0.0) == MLPriorityBand.INFORMATIONAL
    assert map_ml_priority_band(19.9) == MLPriorityBand.INFORMATIONAL


def test_ml_band_low():
    assert map_ml_priority_band(20.0) == MLPriorityBand.LOW
    assert map_ml_priority_band(39.9) == MLPriorityBand.LOW


def test_ml_band_medium():
    assert map_ml_priority_band(40.0) == MLPriorityBand.MEDIUM
    assert map_ml_priority_band(59.9) == MLPriorityBand.MEDIUM


def test_ml_band_high():
    assert map_ml_priority_band(60.0) == MLPriorityBand.HIGH
    assert map_ml_priority_band(79.9) == MLPriorityBand.HIGH


def test_ml_band_critical():
    assert map_ml_priority_band(80.0) == MLPriorityBand.CRITICAL
    assert map_ml_priority_band(100.0) == MLPriorityBand.CRITICAL


def test_ml_band_literals_match_riskv1():
    """ML band string values must match risk-v1 PriorityBand string values."""
    from risk_engine.models import PriorityBand
    for band in MLPriorityBand:
        risk_band = PriorityBand(band.value)
        assert risk_band.value == band.value


def test_ml_score_independent_of_riskv1():
    """calculate_ml_score must never import risk-v1 code."""
    import ml.scorer as scorer_module
    import sys
    # risk_engine must NOT appear in scorer's direct imports.
    scorer_source = scorer_module.__file__
    with open(scorer_source, "r") as f:
        content = f.read()
    assert "risk_engine" not in content, (
        "ml.scorer must not import risk_engine — it must be independent of risk-v1."
    )
