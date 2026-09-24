"""
Phase 6 — Unit tests for ml.labels.

Tests
-----
- Label validation: TRUE_GROUND_TRUTH and ANALYST_LABEL allowed
- Label validation: WEAK_LABEL excluded
- Label validation: UNKNOWN excluded
- Label provenance preserved (label_type stored on LabelRecord)
- WEAK_LABEL never silently converted to ground truth
- Unknown band values excluded
- Dataset statistics report counts for each label type
- check_dataset_sufficiency: SUFFICIENT case
- check_dataset_sufficiency: INSUFFICIENT — too few labels
- check_dataset_sufficiency: INSUFFICIENT — only one class
- check_dataset_sufficiency: INSUFFICIENT — empty input
"""

from __future__ import annotations

import pytest

from ml.constants import DatasetStatus, LabelType
from ml.labels import (
    LabelRecord,
    check_dataset_sufficiency,
    validate_labels,
)


# ── Helper ────────────────────────────────────────────────────────────────────

def _make_raw(label_type: str, priority_band: str, incident_id: str = "inc-1") -> dict:
    return {
        "incident_id": incident_id,
        "label_type": label_type,
        "priority_band": priority_band,
        "source_description": f"test:{label_type}",
    }


# ── validate_labels ───────────────────────────────────────────────────────────

def test_true_ground_truth_label_allowed():
    raw = [_make_raw("TRUE_GROUND_TRUTH", "HIGH")]
    valid, stats = validate_labels(raw)
    assert len(valid) == 1
    assert valid[0].label_type == LabelType.TRUE_GROUND_TRUTH
    assert valid[0].priority_band == "HIGH"
    assert stats.true_ground_truth_count == 1
    assert stats.primary_allowed_count == 1


def test_analyst_label_allowed():
    raw = [_make_raw("ANALYST_LABEL", "CRITICAL")]
    valid, stats = validate_labels(raw)
    assert len(valid) == 1
    assert valid[0].label_type == LabelType.ANALYST_LABEL
    assert stats.analyst_label_count == 1


def test_weak_label_excluded():
    """WEAK_LABEL must NEVER appear in valid records."""
    raw = [_make_raw("WEAK_LABEL", "HIGH")]
    valid, stats = validate_labels(raw)
    assert valid == []
    assert stats.weak_label_count == 1
    assert stats.primary_allowed_count == 0


def test_unknown_label_excluded():
    """UNKNOWN must be excluded from training and evaluation."""
    raw = [_make_raw("UNKNOWN", "MEDIUM")]
    valid, stats = validate_labels(raw)
    assert valid == []
    assert stats.unknown_count == 1


def test_weak_label_never_silently_converted():
    """
    Even if WEAK_LABEL has a valid priority_band, it must NOT be
    promoted to ground truth.
    """
    raw = [
        _make_raw("WEAK_LABEL", "CRITICAL", "inc-1"),
        _make_raw("TRUE_GROUND_TRUTH", "CRITICAL", "inc-2"),
    ]
    valid, stats = validate_labels(raw)
    incident_ids = [r.incident_id for r in valid]
    assert "inc-1" not in incident_ids, "WEAK_LABEL must not appear in valid records"
    assert "inc-2" in incident_ids


def test_label_provenance_preserved():
    """label_type must be preserved on LabelRecord, not discarded."""
    raw = [_make_raw("ANALYST_LABEL", "MEDIUM", "inc-analyst")]
    valid, _ = validate_labels(raw)
    assert valid[0].label_type == LabelType.ANALYST_LABEL
    assert valid[0].source_description == "test:ANALYST_LABEL"


def test_invalid_priority_band_excluded():
    """Records with unrecognised priority_band must be excluded."""
    raw = [_make_raw("TRUE_GROUND_TRUTH", "SUPER_CRITICAL")]
    valid, stats = validate_labels(raw)
    assert valid == []
    assert stats.invalid_band_count == 1


def test_statistics_count_all_label_types():
    """Statistics must accurately report every label type count."""
    raw = [
        _make_raw("TRUE_GROUND_TRUTH", "HIGH", "inc-1"),
        _make_raw("ANALYST_LABEL", "MEDIUM", "inc-2"),
        _make_raw("WEAK_LABEL", "HIGH", "inc-3"),
        _make_raw("UNKNOWN", "LOW", "inc-4"),
    ]
    valid, stats = validate_labels(raw)
    assert stats.total_input == 4
    assert stats.true_ground_truth_count == 1
    assert stats.analyst_label_count == 1
    assert stats.weak_label_count == 1
    assert stats.unknown_count == 1
    assert stats.primary_allowed_count == 2
    assert len(valid) == 2


def test_per_class_counts_in_statistics():
    """statistics.per_class_counts must tally valid labels by band."""
    raw = [
        _make_raw("TRUE_GROUND_TRUTH", "HIGH", "inc-1"),
        _make_raw("ANALYST_LABEL", "HIGH", "inc-2"),
        _make_raw("TRUE_GROUND_TRUTH", "CRITICAL", "inc-3"),
    ]
    _, stats = validate_labels(raw)
    assert stats.per_class_counts["HIGH"] == 2
    assert stats.per_class_counts["CRITICAL"] == 1


# ── check_dataset_sufficiency ─────────────────────────────────────────────────

def _make_valid_records(bands: list[str]) -> list[LabelRecord]:
    return [
        LabelRecord(
            incident_id=f"inc-{i}",
            label_type=LabelType.TRUE_GROUND_TRUTH,
            priority_band=b,
            source_description="test",
        )
        for i, b in enumerate(bands)
    ]


def test_sufficiency_sufficient():
    """Enough labels, enough classes → SUFFICIENT."""
    records = _make_valid_records(["HIGH"] * 6 + ["CRITICAL"] * 6)
    status, msg = check_dataset_sufficiency(records, min_total=10, min_classes=2)
    assert status == DatasetStatus.SUFFICIENT


def test_sufficiency_insufficient_too_few_labels():
    """Fewer labels than min_total → INSUFFICIENT."""
    records = _make_valid_records(["HIGH", "CRITICAL"])  # only 2
    status, msg = check_dataset_sufficiency(records, min_total=10, min_classes=2)
    assert status == DatasetStatus.INSUFFICIENT
    assert "Only 2 valid labels" in msg


def test_sufficiency_insufficient_one_class():
    """Only one class present → INSUFFICIENT."""
    records = _make_valid_records(["HIGH"] * 20)
    status, msg = check_dataset_sufficiency(records, min_total=10, min_classes=2)
    assert status == DatasetStatus.INSUFFICIENT
    assert "1 distinct" in msg or "Only 1" in msg


def test_sufficiency_insufficient_empty():
    """Empty valid_labels → INSUFFICIENT."""
    status, msg = check_dataset_sufficiency([], min_total=10, min_classes=2)
    assert status == DatasetStatus.INSUFFICIENT
    assert "No valid primary labels" in msg
