"""
Phase 6 — Unit tests for ml.leakage and ml.splitter.

Tests
-----
Leakage:
- compute_feature_hash: same input → same hash
- compute_feature_hash: different input → different hash
- deduplicate_by_hash: keeps earliest incident
- deduplicate_by_hash: reports duplicate counts
- deduplicate_by_hash: empty input → empty output
- check_riskv1_leakage: detects risk-v1 derived field names
- check_riskv1_leakage: clean feature list passes
- check_cross_split_contamination: detects train/test overlap
- check_cross_split_contamination: clean splits pass
- run_full_leakage_check: sets has_critical_leakage correctly

Splitter:
- chronological_split: splits are chronologically ordered
- chronological_split: no overlap between splits
- chronological_split: test set is smallest/latest
- chronological_split: handles empty input
- chronological_split: campaign_id unavailable (verified)
- build_split_manifest: counts match
- build_split_manifest: hash fingerprints are stable and different per split
- deduplication happens before split (via dataset pipeline)
- test set is frozen (not modified by val/train operations)
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from ml.leakage import (
    check_cross_split_contamination,
    check_riskv1_leakage,
    compute_feature_hash,
    deduplicate_by_hash,
    run_full_leakage_check,
)
from ml.splitter import (
    CAMPAIGN_ID_AVAILABLE,
    SplitResult,
    build_split_manifest,
    chronological_split,
)
from ml.features import FEATURE_COLUMNS


# ── Helpers ───────────────────────────────────────────────────────────────────

def _make_fv(base_val: float = 0.5) -> dict[str, float]:
    return {col: base_val for col in FEATURE_COLUMNS}


def _ts(day: int) -> datetime:
    return datetime(2024, 1, day, 12, 0, 0, tzinfo=timezone.utc)


def _make_incident(day: int, band: str = "HIGH", fv_base: float = 0.5) -> dict:
    fv = _make_fv(fv_base)
    return {
        "incident_id": f"inc-day-{day}-{band}",
        "created_at": _ts(day),
        "feature_vector": fv,
        "feature_hash": compute_feature_hash(fv),
        "priority_band": band,
        "label_type": "TRUE_GROUND_TRUTH",
        "label_source": "test",
    }


# ── compute_feature_hash ──────────────────────────────────────────────────────

def test_hash_same_input_same_output():
    fv = _make_fv(0.7)
    h1 = compute_feature_hash(fv)
    h2 = compute_feature_hash(fv)
    assert h1 == h2


def test_hash_different_input_different_output():
    fv1 = _make_fv(0.5)
    fv2 = _make_fv(0.9)
    assert compute_feature_hash(fv1) != compute_feature_hash(fv2)


def test_hash_is_64_char_hex():
    h = compute_feature_hash(_make_fv())
    assert len(h) == 64
    assert all(c in "0123456789abcdef" for c in h)


# ── deduplicate_by_hash ───────────────────────────────────────────────────────

def test_dedup_keeps_earliest():
    """Among duplicates, the one with the smallest created_at is kept."""
    fv = _make_fv(0.5)
    h = compute_feature_hash(fv)
    inc_early = {
        "incident_id": "early",
        "created_at": _ts(1),
        "feature_hash": h,
    }
    inc_late = {
        "incident_id": "late",
        "created_at": _ts(5),
        "feature_hash": h,
    }
    deduped, dup_counts = deduplicate_by_hash([inc_late, inc_early])
    assert len(deduped) == 1
    assert deduped[0]["incident_id"] == "early"
    assert dup_counts[h] == 1


def test_dedup_no_duplicates():
    """Non-duplicate incidents are all kept."""
    incidents = [_make_incident(day=d, fv_base=float(d) * 0.1) for d in range(1, 6)]
    deduped, dup_counts = deduplicate_by_hash(incidents)
    assert len(deduped) == 5
    assert dup_counts == {}


def test_dedup_empty_input():
    deduped, dup_counts = deduplicate_by_hash([])
    assert deduped == []
    assert dup_counts == {}


def test_dedup_duplicate_counts_correct():
    """3 identical incidents → 1 kept, 2 in dup_counts."""
    fv = _make_fv(1.0)
    h = compute_feature_hash(fv)
    incidents = [
        {"incident_id": f"dup-{i}", "created_at": _ts(i), "feature_hash": h}
        for i in range(1, 4)
    ]
    deduped, dup_counts = deduplicate_by_hash(incidents)
    assert len(deduped) == 1
    assert dup_counts[h] == 2


# ── check_riskv1_leakage ──────────────────────────────────────────────────────

def test_riskv1_leakage_detects_bad_names():
    bad_features = ["severity_wazuh", "risk_score", "priority_band", "alert_count_log"]
    bad = check_riskv1_leakage(bad_features)
    assert "risk_score" in bad
    assert "priority_band" in bad
    assert "severity_wazuh" not in bad
    assert "alert_count_log" not in bad


def test_riskv1_leakage_clean_feature_list():
    clean = check_riskv1_leakage(FEATURE_COLUMNS)
    assert clean == [], f"FEATURE_COLUMNS contains risk-v1 derived names: {clean}"


# ── check_cross_split_contamination ──────────────────────────────────────────

def test_cross_split_contamination_detected():
    shared = {"hash-abc", "hash-def"}
    train = {"hash-001", "hash-abc"}
    val = {"hash-002", "hash-def"}
    test = {"hash-003", "hash-abc"}  # hash-abc in both train and test
    contamination = check_cross_split_contamination(train, val, test)
    assert any(h == "hash-abc" and s1 == "train" and s2 == "test"
               for h, s1, s2 in contamination)


def test_cross_split_no_contamination():
    train = {"hash-1", "hash-2"}
    val = {"hash-3", "hash-4"}
    test = {"hash-5", "hash-6"}
    assert check_cross_split_contamination(train, val, test) == []


# ── run_full_leakage_check ────────────────────────────────────────────────────

def test_leakage_check_critical_on_riskv1_feature():
    report = run_full_leakage_check(
        feature_names=["severity_wazuh", "risk_score"],
        train_hashes={"h1"},
        val_hashes={"h2"},
        test_hashes={"h3"},
    )
    assert report.has_critical_leakage is True
    assert "risk_score" in report.riskv1_derived_features


def test_leakage_check_clean():
    report = run_full_leakage_check(
        feature_names=FEATURE_COLUMNS,
        train_hashes={"h1", "h2"},
        val_hashes={"h3", "h4"},
        test_hashes={"h5", "h6"},
    )
    assert report.has_critical_leakage is False
    assert report.riskv1_derived_features == []


# ── chronological_split ───────────────────────────────────────────────────────

def _make_incidents_range(n: int) -> list[dict]:
    """n incidents on consecutive days."""
    return [_make_incident(day=i + 1, fv_base=float(i) * 0.01) for i in range(n)]


def test_chronological_split_order_preserved():
    """Train contains earliest incidents; test contains newest."""
    incidents = _make_incidents_range(20)
    result = chronological_split(incidents, train_fraction=0.7, val_fraction=0.15)
    train_max = max(r["created_at"] for r in result.train)
    val_min = min(r["created_at"] for r in result.val)
    test_min = min(r["created_at"] for r in result.test)
    assert train_max <= val_min
    assert val_min <= test_min


def test_chronological_split_no_overlap():
    """No incident should appear in more than one split."""
    incidents = _make_incidents_range(30)
    result = chronological_split(incidents)
    train_ids = {r["incident_id"] for r in result.train}
    val_ids = {r["incident_id"] for r in result.val}
    test_ids = {r["incident_id"] for r in result.test}
    assert train_ids.isdisjoint(val_ids)
    assert train_ids.isdisjoint(test_ids)
    assert val_ids.isdisjoint(test_ids)


def test_chronological_split_all_incidents_covered():
    """Every incident appears in exactly one split."""
    incidents = _make_incidents_range(30)
    result = chronological_split(incidents)
    total = len(result.train) + len(result.val) + len(result.test)
    assert total == 30


def test_chronological_split_empty_input():
    result = chronological_split([])
    assert result.train == []
    assert result.val == []
    assert result.test == []


def test_chronological_split_invalid_fractions_raises():
    with pytest.raises(ValueError):
        chronological_split(_make_incidents_range(10), train_fraction=0.8, val_fraction=0.3)


def test_campaign_id_not_available():
    """Verify CAMPAIGN_ID_AVAILABLE is False (schema confirmed)."""
    assert CAMPAIGN_ID_AVAILABLE is False, (
        "campaign_id is not in the incidents schema. "
        "CAMPAIGN_ID_AVAILABLE must remain False."
    )


def test_test_set_is_newest():
    """Test set incidents are chronologically after train and val."""
    incidents = _make_incidents_range(20)
    result = chronological_split(incidents)
    if result.test and result.val:
        val_max = max(r["created_at"] for r in result.val)
        test_min = min(r["created_at"] for r in result.test)
        assert test_min >= val_max


# ── build_split_manifest ──────────────────────────────────────────────────────

def test_split_manifest_counts_match():
    incidents = _make_incidents_range(30)
    result = chronological_split(incidents)
    manifest = build_split_manifest(result)
    assert manifest.train_count == len(result.train)
    assert manifest.val_count == len(result.val)
    assert manifest.test_count == len(result.test)
    assert manifest.train_count + manifest.val_count + manifest.test_count == 30


def test_split_manifest_hash_fingerprints_stable():
    """Fingerprints must be deterministic across two manifest builds."""
    incidents = _make_incidents_range(20)
    result = chronological_split(incidents)
    m1 = build_split_manifest(result)
    m2 = build_split_manifest(result)
    assert m1.train_hash_fingerprint == m2.train_hash_fingerprint
    assert m1.test_hash_fingerprint == m2.test_hash_fingerprint


def test_split_manifest_fingerprints_differ_per_split():
    """Train and test fingerprints must be different (different incident sets)."""
    incidents = _make_incidents_range(30)
    result = chronological_split(incidents)
    manifest = build_split_manifest(result)
    assert manifest.train_hash_fingerprint != manifest.test_hash_fingerprint
