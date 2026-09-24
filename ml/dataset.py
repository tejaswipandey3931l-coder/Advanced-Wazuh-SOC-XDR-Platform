"""
Phase 6 — Dataset construction pipeline.

This module orchestrates the complete dataset-building process:

  1. Inspect available incident timestamps (data-driven time window).
  2. Apply optional configured boundaries (DATASET_START / DATASET_END).
  3. Apply inclusion/exclusion criteria.
  4. Attach ground-truth labels (only TRUE_GROUND_TRUTH + ANALYST_LABEL).
  5. Extract T_prediction-safe features.
  6. Compute deterministic feature hashes.
  7. Deduplicate (before any split).
  8. Generate statistics and determine DATASET_STATUS.

If DATASET_STATUS == INSUFFICIENT, the pipeline STOPS here and produces
a diagnostic report.  No synthetic or lab data is injected into the
primary dataset.

The pipeline does NOT create production database tables.  All artefacts
are research-only flat files (JSON manifests, etc.).
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any

from .constants import DatasetStatus, LabelType, PRIORITY_CLASS_ORDER
from .features import FEATURE_SCHEMA_VERSION, extract_features, compute_incident_age_minutes
from .labels import LabelRecord, LabelStatistics, validate_labels, check_dataset_sufficiency
from .leakage import compute_feature_hash, deduplicate_by_hash


@dataclass
class DatasetInspectionReport:
    """Summary of available data before any filtering."""

    min_timestamp: str = ""
    max_timestamp: str = ""
    total_incidents: int = 0
    configured_start: str | None = None
    configured_end: str | None = None
    eligible_after_window: int = 0


@dataclass
class DatasetStatistics:
    """Full statistics produced by the dataset pipeline."""

    inspection: DatasetInspectionReport = field(
        default_factory=DatasetInspectionReport
    )
    total_after_inclusion: int = 0
    excluded_no_severity: int = 0
    excluded_no_timestamp: int = 0
    excluded_no_label: int = 0
    label_statistics: dict[str, Any] = field(default_factory=dict)
    total_before_dedup: int = 0
    total_after_dedup: int = 0
    duplicates_removed: int = 0
    status: str = DatasetStatus.UNKNOWN.value
    status_message: str = ""
    feature_schema_version: str = FEATURE_SCHEMA_VERSION


@dataclass
class BuiltDataset:
    """The complete output of the dataset pipeline."""

    records: list[dict] = field(default_factory=list)
    statistics: DatasetStatistics = field(default_factory=DatasetStatistics)
    status: DatasetStatus = DatasetStatus.UNKNOWN
    diagnostic_report: str = ""


def inspect_available_data(
    incidents: list[dict],
    configured_start: datetime | None = None,
    configured_end: datetime | None = None,
) -> DatasetInspectionReport:
    """
    Inspect the available incidents and report the discoverable time range.

    This runs before any filtering so the report reflects the raw state of
    the database.

    Parameters
    ----------
    incidents:
        All incidents available (list of raw incident dicts).  Each must
        contain at least ``created_at`` (datetime).
    configured_start, configured_end:
        Optional user-configured boundaries.  If omitted, the full
        discovered range is used.

    Returns
    -------
    DatasetInspectionReport
    """
    timestamps = [inc["created_at"] for inc in incidents if "created_at" in inc]
    report = DatasetInspectionReport(
        total_incidents=len(incidents),
        configured_start=configured_start.isoformat() if configured_start else None,
        configured_end=configured_end.isoformat() if configured_end else None,
    )
    if timestamps:
        report.min_timestamp = min(timestamps).isoformat()
        report.max_timestamp = max(timestamps).isoformat()
    return report


def build_dataset(
    raw_incidents: list[dict],
    raw_labels: list[dict],
    t_prediction: datetime,
    configured_start: datetime | None = None,
    configured_end: datetime | None = None,
) -> BuiltDataset:
    """
    Execute the full dataset construction pipeline.

    Parameters
    ----------
    raw_incidents:
        All incidents from the database.  Each dict must contain:
          - ``incident_id`` (str)
          - ``created_at`` (datetime)
          - ``severity`` (str)
          - ``alert_count`` (int)
          - ``correlation_rule_type`` (str | None)
          - ``correlation_confidence`` (float | None)
          - ``cti_records`` (list[dict])  – each with ``queried_at`` + ``confidence``
          - ``mitre_tactics`` (list[str])
          - ``evidence_version`` (int | None)
    raw_labels:
        Label provenance records (see ml.labels.validate_labels()).
    t_prediction:
        Logical evidence cutoff for feature extraction.
    configured_start, configured_end:
        Optional configurable window boundaries.

    Returns
    -------
    BuiltDataset
        If status == INSUFFICIENT, records is empty and diagnostic_report
        contains the reason.
    """
    stats = DatasetStatistics()
    stats.feature_schema_version = FEATURE_SCHEMA_VERSION

    # 1. Inspect available data (data-driven, no hard-coded dates).
    inspection = inspect_available_data(raw_incidents, configured_start, configured_end)
    stats.inspection = inspection

    # 2. Apply configured time window.
    window_incidents = _apply_time_window(
        raw_incidents, configured_start, configured_end
    )
    inspection.eligible_after_window = len(window_incidents)

    # 3. Validate labels (applies policy: TRUE_GROUND_TRUTH + ANALYST_LABEL only).
    valid_labels, label_stats = validate_labels(raw_labels)
    stats.label_statistics = {
        "total_input": label_stats.total_input,
        "true_ground_truth_count": label_stats.true_ground_truth_count,
        "analyst_label_count": label_stats.analyst_label_count,
        "weak_label_count": label_stats.weak_label_count,
        "unknown_count": label_stats.unknown_count,
        "invalid_band_count": label_stats.invalid_band_count,
        "primary_allowed_count": label_stats.primary_allowed_count,
        "per_class_counts": label_stats.per_class_counts,
    }

    # Build label lookup.
    label_lookup: dict[str, LabelRecord] = {
        r.incident_id: r for r in valid_labels
    }

    # 4. Apply inclusion/exclusion criteria and build feature records.
    records_pre_dedup: list[dict] = []
    excluded_no_severity = 0
    excluded_no_timestamp = 0
    excluded_no_label = 0

    for inc in window_incidents:
        # Must have severity and created_at.
        if not inc.get("severity"):
            excluded_no_severity += 1
            continue
        if not inc.get("created_at"):
            excluded_no_timestamp += 1
            continue

        # Must have a valid primary label.
        incident_id = str(inc.get("incident_id", ""))
        if incident_id not in label_lookup:
            excluded_no_label += 1
            continue

        label_rec = label_lookup[incident_id]

        # 5. Extract T_prediction-safe features.
        try:
            fv = extract_features(
                incident_id=incident_id,
                created_at=inc["created_at"],
                severity=inc["severity"],
                alert_count=int(inc.get("alert_count", 1)),
                correlation_rule_type=inc.get("correlation_rule_type"),
                correlation_confidence=inc.get("correlation_confidence"),
                cti_records=inc.get("cti_records", []),
                mitre_tactics=inc.get("mitre_tactics", []),
                t_prediction=t_prediction,
            )
        except Exception as exc:
            # Log and skip; do not crash the pipeline.
            continue

        # 6. Compute feature hash.
        feature_hash = compute_feature_hash(fv)

        records_pre_dedup.append({
            "incident_id": incident_id,
            "created_at": inc["created_at"],
            "feature_vector": fv,
            "feature_hash": feature_hash,
            "priority_band": label_rec.priority_band,
            "label_type": label_rec.label_type.value,
            "label_source": label_rec.source_description,
        })

    stats.total_after_inclusion = len(records_pre_dedup)
    stats.excluded_no_severity = excluded_no_severity
    stats.excluded_no_timestamp = excluded_no_timestamp
    stats.excluded_no_label = excluded_no_label
    stats.total_before_dedup = len(records_pre_dedup)

    # 7. Deduplicate BEFORE split.
    deduplicated, dup_counts = deduplicate_by_hash(records_pre_dedup)
    stats.total_after_dedup = len(deduplicated)
    stats.duplicates_removed = sum(dup_counts.values())

    # 8. Check dataset sufficiency.
    label_records_for_gate = [
        LabelRecord(
            incident_id=r["incident_id"],
            label_type=LabelType(r["label_type"]),
            priority_band=r["priority_band"],
            source_description=r.get("label_source", ""),
        )
        for r in deduplicated
    ]
    ds_status, ds_message = check_dataset_sufficiency(label_records_for_gate)
    stats.status = ds_status.value
    stats.status_message = ds_message

    if ds_status == DatasetStatus.INSUFFICIENT:
        return BuiltDataset(
            records=[],
            statistics=stats,
            status=DatasetStatus.INSUFFICIENT,
            diagnostic_report=_format_diagnostic(stats, ds_message),
        )

    return BuiltDataset(
        records=deduplicated,
        statistics=stats,
        status=DatasetStatus.SUFFICIENT,
        diagnostic_report="",
    )


def _apply_time_window(
    incidents: list[dict],
    start: datetime | None,
    end: datetime | None,
) -> list[dict]:
    """Filter incidents to the configured time window (both bounds inclusive)."""
    result = []
    for inc in incidents:
        ts = inc.get("created_at")
        if ts is None:
            continue
        if ts.tzinfo is None:
            ts = ts.replace(tzinfo=timezone.utc)
        if start and ts < start:
            continue
        if end and ts > end:
            continue
        result.append(inc)
    return result


def _format_diagnostic(
    stats: DatasetStatistics,
    ds_message: str,
) -> str:
    """Format a human-readable diagnostic report for an INSUFFICIENT dataset."""
    lines = [
        "=" * 70,
        "PHASE 6 — DATASET STATUS: INSUFFICIENT",
        "=" * 70,
        "",
        "Data inspection:",
        f"  min_timestamp    : {stats.inspection.min_timestamp or 'N/A'}",
        f"  max_timestamp    : {stats.inspection.max_timestamp or 'N/A'}",
        f"  total_incidents  : {stats.inspection.total_incidents}",
        f"  in_window        : {stats.inspection.eligible_after_window}",
        "",
        "Label counts:",
        f"  TRUE_GROUND_TRUTH : {stats.label_statistics.get('true_ground_truth_count', 0)}",
        f"  ANALYST_LABEL     : {stats.label_statistics.get('analyst_label_count', 0)}",
        f"  WEAK_LABEL        : {stats.label_statistics.get('weak_label_count', 0)} (excluded)",
        f"  UNKNOWN           : {stats.label_statistics.get('unknown_count', 0)} (excluded)",
        "",
        "After filters:",
        f"  eligible records  : {stats.total_after_dedup}",
        "",
        "Reason:",
        f"  {ds_message}",
        "",
        "Action: Collect more labeled incident-level data before training.",
        "Do NOT fabricate a dataset or train a model on insufficient data.",
        "=" * 70,
    ]
    return "\n".join(lines)
