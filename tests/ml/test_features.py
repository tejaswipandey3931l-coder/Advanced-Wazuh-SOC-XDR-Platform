"""
Phase 6 — Unit tests for ml.features.

Tests
-----
- feature timestamp enforcement (T_prediction leakage prevention)
- incident_age_minutes: normal positive age
- incident_age_minutes: equal timestamps → 0
- incident_age_minutes: future created_at relative to T_prediction → 0
- incident_age_minutes: deterministic repeated calculation
- deterministic feature generation (same inputs → same output)
- CTI records after T_prediction are excluded
- CTI records before/at T_prediction are included
- Feature vector contains all declared FEATURE_COLUMNS
- Feature values are bounded correctly
- Missing CTI records → 0 counts / confidences
- No risk-v1 derived fields in FEATURE_COLUMNS
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from ml.features import (
    FEATURE_COLUMNS,
    compute_incident_age_minutes,
    extract_features,
    feature_vector_as_list,
    _filter_cti_by_t_prediction,
)
from ml.leakage import _RISK_V1_DERIVED_NAMES


# ── Helpers ───────────────────────────────────────────────────────────────────

def _now() -> datetime:
    return datetime(2024, 6, 15, 12, 0, 0, tzinfo=timezone.utc)


def _make_cti(queried_at: datetime, confidence: float = 0.8) -> dict:
    return {"queried_at": queried_at, "confidence": confidence}


def _base_features(**overrides) -> dict:
    now = _now()
    defaults = dict(
        incident_id="test-001",
        created_at=now - timedelta(hours=2),
        severity="medium",
        alert_count=5,
        correlation_rule_type="sequence",
        correlation_confidence=0.7,
        cti_records=[_make_cti(now - timedelta(hours=1))],
        mitre_tactics=["execution", "persistence"],
        t_prediction=now,
    )
    defaults.update(overrides)
    return defaults


# ── incident_age_minutes tests ────────────────────────────────────────────────

def test_incident_age_normal_positive():
    """Normal case: T_prediction 90 minutes after created_at → 90.0."""
    created = datetime(2024, 1, 1, 10, 0, 0, tzinfo=timezone.utc)
    t_pred = datetime(2024, 1, 1, 11, 30, 0, tzinfo=timezone.utc)
    age = compute_incident_age_minutes(created, t_pred)
    assert age == pytest.approx(90.0)


def test_incident_age_equal_timestamps_gives_zero():
    """T_prediction == created_at → 0.0."""
    ts = datetime(2024, 1, 1, 10, 0, 0, tzinfo=timezone.utc)
    age = compute_incident_age_minutes(ts, ts)
    assert age == pytest.approx(0.0)


def test_incident_age_future_created_at_clamped_to_zero():
    """created_at > T_prediction (future) → clamped to 0.0."""
    t_pred = datetime(2024, 1, 1, 10, 0, 0, tzinfo=timezone.utc)
    created = datetime(2024, 1, 1, 11, 0, 0, tzinfo=timezone.utc)  # 1h future
    age = compute_incident_age_minutes(created, t_pred)
    assert age == pytest.approx(0.0)


def test_incident_age_deterministic():
    """Same inputs always produce the same result."""
    created = datetime(2024, 3, 1, 8, 0, 0, tzinfo=timezone.utc)
    t_pred = datetime(2024, 3, 1, 9, 15, 0, tzinfo=timezone.utc)
    a1 = compute_incident_age_minutes(created, t_pred)
    a2 = compute_incident_age_minutes(created, t_pred)
    assert a1 == a2
    assert a1 == pytest.approx(75.0)


def test_incident_age_naive_datetime_handled():
    """Naive datetimes (no tzinfo) should be handled without crashing."""
    created = datetime(2024, 1, 1, 10, 0, 0)  # naive
    t_pred = datetime(2024, 1, 1, 11, 0, 0)   # naive
    age = compute_incident_age_minutes(created, t_pred)
    assert age == pytest.approx(60.0)


# ── T_prediction leakage prevention ──────────────────────────────────────────

def test_cti_after_t_prediction_excluded():
    """CTI record queried AFTER T_prediction must be excluded."""
    now = _now()
    future_cti = _make_cti(queried_at=now + timedelta(hours=1), confidence=0.99)
    filtered = _filter_cti_by_t_prediction([future_cti], t_prediction=now)
    assert filtered == []


def test_cti_at_t_prediction_included():
    """CTI record queried AT T_prediction must be included."""
    now = _now()
    exact_cti = _make_cti(queried_at=now, confidence=0.5)
    filtered = _filter_cti_by_t_prediction([exact_cti], t_prediction=now)
    assert len(filtered) == 1


def test_cti_before_t_prediction_included():
    """CTI record queried before T_prediction must be included."""
    now = _now()
    past_cti = _make_cti(queried_at=now - timedelta(hours=6), confidence=0.7)
    filtered = _filter_cti_by_t_prediction([past_cti], t_prediction=now)
    assert len(filtered) == 1


def test_cti_mix_filters_only_future():
    """Mix of past, present, and future CTI: only past and present are included."""
    now = _now()
    past = _make_cti(now - timedelta(hours=2), confidence=0.6)
    exact = _make_cti(now, confidence=0.5)
    future = _make_cti(now + timedelta(minutes=1), confidence=0.99)
    filtered = _filter_cti_by_t_prediction([past, exact, future], t_prediction=now)
    assert len(filtered) == 2
    confidences = [r["confidence"] for r in filtered]
    assert 0.99 not in confidences


def test_cti_missing_queried_at_excluded():
    """CTI record missing queried_at must be conservatively excluded."""
    record_no_ts = {"confidence": 0.8}
    filtered = _filter_cti_by_t_prediction([record_no_ts], t_prediction=_now())
    assert filtered == []


# ── extract_features tests ────────────────────────────────────────────────────

def test_extract_features_returns_all_columns():
    """Feature dict must contain every key listed in FEATURE_COLUMNS."""
    fv = extract_features(**_base_features())
    missing = [col for col in FEATURE_COLUMNS if col not in fv]
    assert missing == [], f"Missing columns: {missing}"


def test_extract_features_deterministic():
    """Same inputs always produce the same feature vector."""
    fv1 = extract_features(**_base_features())
    fv2 = extract_features(**_base_features())
    assert fv1 == fv2


def test_severity_wazuh_normalised():
    """severity_wazuh must be within (0, 1]."""
    for sev in ["informational", "low", "medium", "high", "critical"]:
        fv = extract_features(**_base_features(severity=sev))
        assert 0.0 <= fv["severity_wazuh"] <= 1.0


def test_corr_rule_type_one_hot_sequence():
    """sequence rule type → corr_rule_type_sequence == 1.0, others == 0."""
    fv = extract_features(**_base_features(correlation_rule_type="sequence"))
    assert fv["corr_rule_type_sequence"] == 1.0
    assert fv["corr_rule_type_entity_group"] == 0.0
    assert fv["corr_rule_type_temporal"] == 0.0
    assert fv["corr_rule_type_unknown"] == 0.0


def test_corr_rule_type_one_hot_unknown():
    """None rule type → corr_rule_type_unknown == 1.0."""
    fv = extract_features(**_base_features(correlation_rule_type=None))
    assert fv["corr_rule_type_unknown"] == 1.0
    assert fv["corr_rule_type_sequence"] == 0.0


def test_cti_max_confidence_respects_t_prediction():
    """cti_max_confidence must only reflect CTI records ≤ T_prediction."""
    now = _now()
    valid_cti = _make_cti(now - timedelta(hours=1), confidence=0.7)
    leaked_cti = _make_cti(now + timedelta(hours=1), confidence=0.99)
    fv = extract_features(
        **_base_features(cti_records=[valid_cti, leaked_cti], t_prediction=now)
    )
    assert fv["cti_max_confidence"] == pytest.approx(0.7)


def test_no_cti_gives_zero_confidence_and_count():
    """No CTI records → cti_max_confidence == 0.0, ioc_count == 0."""
    fv = extract_features(**_base_features(cti_records=[]))
    assert fv["cti_max_confidence"] == pytest.approx(0.0)
    assert fv["ioc_count"] == pytest.approx(0.0)


def test_incident_age_minutes_in_feature_vector():
    """incident_age_minutes feature must be ≥ 0 and equal to direct computation."""
    now = _now()
    created = now - timedelta(minutes=45)
    fv = extract_features(**_base_features(created_at=created, t_prediction=now))
    assert fv["incident_age_minutes"] == pytest.approx(45.0)


def test_incident_age_future_created_gives_zero_in_features():
    """Future created_at relative to T_prediction → incident_age_minutes == 0.0."""
    now = _now()
    fv = extract_features(
        **_base_features(
            created_at=now + timedelta(hours=1),
            t_prediction=now,
        )
    )
    assert fv["incident_age_minutes"] == pytest.approx(0.0)


def test_feature_vector_as_list_length():
    """feature_vector_as_list must return exactly len(FEATURE_COLUMNS) values."""
    fv = extract_features(**_base_features())
    vec = feature_vector_as_list(fv)
    assert len(vec) == len(FEATURE_COLUMNS)


# ── No risk-v1 derived fields in FEATURE_COLUMNS ─────────────────────────────

def test_feature_columns_contain_no_riskv1_derived_names():
    """FEATURE_COLUMNS must not overlap with any risk-v1 derived field names."""
    overlap = set(FEATURE_COLUMNS) & _RISK_V1_DERIVED_NAMES
    assert overlap == set(), (
        f"FEATURE_COLUMNS contain risk-v1 derived name(s): {overlap}"
    )
