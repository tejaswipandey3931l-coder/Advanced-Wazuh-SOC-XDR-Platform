"""
Phase 6 — Label validation and provenance.

Label Policy
------------
PRIMARY SUPERVISED LEARNING DATASET:

ALLOWED:
    - TRUE_GROUND_TRUTH   (incident-level authoritative label)
    - ANALYST_LABEL       (manual SOC analyst priority assignment)

EXCLUDED:
    - WEAK_LABEL          (never promoted to ground truth)
    - UNKNOWN             (excluded from training and evaluation)

Rules
-----
1. Label provenance is always preserved; the original LabelType is
   stored alongside the final priority_band string.
2. WEAK_LABELs are never silently converted to ground truth.
3. UNKNOWN incidents are excluded entirely.
4. Dataset statistics must report counts for each label type.
5. If insufficient valid labels remain after filtering, the pipeline
   sets DATASET_STATUS = INSUFFICIENT and halts training.
6. No fabricated or synthetic records may be injected into the primary
   real-world dataset.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .constants import DatasetStatus, LabelType, PRIORITY_CLASS_ORDER


@dataclass
class LabelRecord:
    """A validated incident label with full provenance metadata."""

    incident_id: str
    label_type: LabelType
    priority_band: str  # One of PRIORITY_CLASS_ORDER uppercase literals
    source_description: str  # Human-readable provenance annotation

    def is_primary_allowed(self) -> bool:
        """Return True if this label may be used in primary training/evaluation."""
        return self.label_type in (
            LabelType.TRUE_GROUND_TRUTH,
            LabelType.ANALYST_LABEL,
        )


@dataclass
class LabelStatistics:
    """Per-label-type and per-class counts produced by validate_labels()."""

    total_input: int = 0
    true_ground_truth_count: int = 0
    analyst_label_count: int = 0
    weak_label_count: int = 0
    unknown_count: int = 0
    invalid_band_count: int = 0
    primary_allowed_count: int = 0
    per_class_counts: dict[str, int] = field(default_factory=dict)


def validate_labels(
    raw_labels: list[dict],
) -> tuple[list[LabelRecord], LabelStatistics]:
    """
    Validate and filter a list of raw label dicts against the label policy.

    Parameters
    ----------
    raw_labels:
        Each dict must contain:
          - ``incident_id``       (str)   – incident UUID.
          - ``label_type``        (str)   – one of LabelType literal values.
          - ``priority_band``     (str)   – one of PRIORITY_CLASS_ORDER literals.
          - ``source_description`` (str)  – provenance annotation.

    Returns
    -------
    (valid_records, statistics)
        ``valid_records`` contains only ALLOWED labels (TRUE_GROUND_TRUTH,
        ANALYST_LABEL) with a recognised priority_band.
        ``statistics`` contains counts for every label type including
        excluded ones.
    """
    stats = LabelStatistics()
    valid: list[LabelRecord] = {}  # type: ignore[assignment]
    valid = []

    for raw in raw_labels:
        stats.total_input += 1

        incident_id = str(raw.get("incident_id", ""))
        label_type_str = str(raw.get("label_type", "UNKNOWN")).upper()
        priority_band = str(raw.get("priority_band", "")).upper()
        source_desc = str(raw.get("source_description", ""))

        # ── Parse label type ────────────────────────────────────────────────
        try:
            label_type = LabelType(label_type_str)
        except ValueError:
            label_type = LabelType.UNKNOWN

        # ── Count by type ───────────────────────────────────────────────────
        if label_type == LabelType.TRUE_GROUND_TRUTH:
            stats.true_ground_truth_count += 1
        elif label_type == LabelType.ANALYST_LABEL:
            stats.analyst_label_count += 1
        elif label_type == LabelType.WEAK_LABEL:
            stats.weak_label_count += 1
            # WEAK_LABEL is never promoted — skip.
            continue
        else:
            stats.unknown_count += 1
            # UNKNOWN excluded from training and evaluation — skip.
            continue

        # ── Validate priority band ──────────────────────────────────────────
        if priority_band not in PRIORITY_CLASS_ORDER:
            stats.invalid_band_count += 1
            continue

        record = LabelRecord(
            incident_id=incident_id,
            label_type=label_type,
            priority_band=priority_band,
            source_description=source_desc,
        )
        valid.append(record)
        stats.primary_allowed_count += 1
        stats.per_class_counts[priority_band] = (
            stats.per_class_counts.get(priority_band, 0) + 1
        )

    return valid, stats


def check_dataset_sufficiency(
    valid_labels: list[LabelRecord],
    min_total: int = 10,
    min_classes: int = 2,
) -> tuple[DatasetStatus, str]:
    """
    Apply the label availability gate before training.

    Conditions for SUFFICIENT:
      1. At least ``min_total`` valid labels.
      2. At least ``min_classes`` distinct priority classes represented.

    If either condition fails, returns INSUFFICIENT with a diagnostic message.

    Parameters
    ----------
    valid_labels:
        Output of validate_labels() (already filtered to primary-allowed).
    min_total:
        Minimum number of labeled incidents required to attempt training.
    min_classes:
        Minimum number of distinct priority classes required.

    Returns
    -------
    (DatasetStatus, diagnostic_message)
    """
    if not valid_labels:
        return DatasetStatus.INSUFFICIENT, (
            "No valid primary labels found. "
            "All incidents either lack TRUE_GROUND_TRUTH / ANALYST_LABEL, "
            "or have no recognised priority band."
        )

    n = len(valid_labels)
    classes = set(r.priority_band for r in valid_labels)
    n_classes = len(classes)

    if n < min_total:
        return DatasetStatus.INSUFFICIENT, (
            f"Only {n} valid labels found (minimum required: {min_total}). "
            f"Classes present: {sorted(classes)}. "
            "Collect more labeled incidents before training."
        )

    if n_classes < min_classes:
        return DatasetStatus.INSUFFICIENT, (
            f"Only {n_classes} distinct priority class(es) present: "
            f"{sorted(classes)}. "
            f"Minimum required: {min_classes}. "
            "Ensure the labeled dataset spans multiple priority levels."
        )

    return DatasetStatus.SUFFICIENT, (
        f"Dataset sufficient: {n} valid labels across "
        f"{n_classes} classes ({sorted(classes)})."
    )
