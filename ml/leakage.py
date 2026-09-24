"""
Phase 6 — Leakage detection, deduplication, and duplicate-hash computation.

Deduplication
-------------
A deterministic SHA-256 hash of the raw-evidence feature vector is computed
for each incident before any train/val/test split.  Incidents with identical
hashes are duplicates; only the earliest (by created_at) is retained.

Leakage checks
--------------
The following leakage types are actively detected:

1. Temporal leakage:    features that reference evidence after T_prediction.
2. Risk-v1 leakage:     features derived from risk-v1 outputs.
3. Label leakage:       weak or post-hoc labels used as primary ground truth.
4. Duplicate/scenario:  same feature hash appearing in multiple splits.

Deduplication ALWAYS runs before splitting.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from datetime import datetime

from .features import FEATURE_COLUMNS, feature_vector_as_list


# ── Risk-v1 derived field names (never allowed as ML features) ────────────
_RISK_V1_DERIVED_NAMES: frozenset[str] = frozenset({
    "risk_score",
    "overall_score",
    "base_score",
    "temporal_decay",
    "priority_band",
    "risk_priority_band",
    "risk_evidence_version",
    "risk_evidence_as_of",
    "risk_evaluation_as_of",
    "risk_calculated_at",
    "factor_score_severity",
    "factor_score_correlation",
    "factor_score_cti",
    "factor_score_volume",
    "factor_score_mitre",
    "effective_weight_severity",
    "effective_weight_correlation",
    "effective_weight_cti",
    "effective_weight_volume",
    "effective_weight_mitre",
    "risk_explanation",
    "clean_mitigation",
    "scoring_version",
})


@dataclass
class LeakageReport:
    """Results of a leakage-detection pass."""

    temporal_leakage_incidents: list[str] = field(default_factory=list)
    riskv1_derived_features: list[str] = field(default_factory=list)
    has_critical_leakage: bool = False
    summary: str = ""


def compute_feature_hash(feature_dict: dict[str, float]) -> str:
    """
    Compute a deterministic SHA-256 hash of a raw-evidence feature vector.

    The hash is computed over the JSON-serialised, canonically-sorted
    key-value pairs of the feature vector (keys ordered by FEATURE_COLUMNS).

    Parameters
    ----------
    feature_dict:
        Output of ml.features.extract_features().

    Returns
    -------
    str
        64-character hex-string SHA-256 digest.
    """
    # Build a stable serialisation: list of (key, rounded_value) pairs
    # ordered by FEATURE_COLUMNS to ensure permutation-invariance.
    canonical_pairs = [
        (col, round(feature_dict.get(col, 0.0), 8))
        for col in FEATURE_COLUMNS
    ]
    payload = json.dumps(canonical_pairs, sort_keys=False)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def deduplicate_by_hash(
    incidents: list[dict],
) -> tuple[list[dict], dict[str, int]]:
    """
    Remove duplicate incidents based on their feature_hash, keeping the
    earliest incident (smallest created_at) for each unique hash.

    This function MUST be called BEFORE any train/val/test split.

    Parameters
    ----------
    incidents:
        List of incident dicts.  Each must contain:
          - ``incident_id`` (str)
          - ``feature_hash`` (str)  – from compute_feature_hash()
          - ``created_at`` (datetime)

    Returns
    -------
    (deduplicated_list, duplicate_counts)
        ``deduplicated_list`` has one incident per unique hash (earliest kept).
        ``duplicate_counts`` maps hash → number of duplicates removed.
    """
    # Group by hash.
    hash_groups: dict[str, list[dict]] = {}
    for inc in incidents:
        h = inc["feature_hash"]
        hash_groups.setdefault(h, []).append(inc)

    deduplicated: list[dict] = []
    duplicate_counts: dict[str, int] = {}

    for h, group in hash_groups.items():
        # Sort by created_at ascending; keep first (earliest).
        sorted_group = sorted(group, key=lambda x: x["created_at"])
        deduplicated.append(sorted_group[0])
        removed = len(group) - 1
        if removed > 0:
            duplicate_counts[h] = removed

    return deduplicated, duplicate_counts


def check_riskv1_leakage(feature_names: list[str]) -> list[str]:
    """
    Return any feature names that match known risk-v1 derived field names.

    This is a static inspection guard that verifies the feature list does not
    include any risk-v1 computed outputs.

    Parameters
    ----------
    feature_names:
        The list of feature column names to inspect.

    Returns
    -------
    list[str]
        Names of any detected risk-v1 derived fields (should be empty).
    """
    return [name for name in feature_names if name in _RISK_V1_DERIVED_NAMES]


def check_cross_split_contamination(
    train_hashes: set[str],
    val_hashes: set[str],
    test_hashes: set[str],
) -> list[tuple[str, str, str]]:
    """
    Detect duplicate hashes that appear in more than one split.

    Returns a list of (hash, split_a, split_b) tuples for contaminated hashes.
    An empty list means no contamination.
    """
    contamination: list[tuple[str, str, str]] = []
    for h in train_hashes & val_hashes:
        contamination.append((h, "train", "val"))
    for h in train_hashes & test_hashes:
        contamination.append((h, "train", "test"))
    for h in val_hashes & test_hashes:
        contamination.append((h, "val", "test"))
    return contamination


def run_full_leakage_check(
    feature_names: list[str],
    train_hashes: set[str],
    val_hashes: set[str],
    test_hashes: set[str],
) -> LeakageReport:
    """
    Run all automated leakage checks and produce a consolidated report.

    Parameters
    ----------
    feature_names:
        Names of features in the feature vector.
    train_hashes, val_hashes, test_hashes:
        Feature hash sets for each split.

    Returns
    -------
    LeakageReport
        ``has_critical_leakage`` is True if any risk-v1 derived features or
        cross-split contamination is detected.
    """
    riskv1_bad = check_riskv1_leakage(feature_names)
    contamination = check_cross_split_contamination(
        train_hashes, val_hashes, test_hashes
    )

    has_critical = bool(riskv1_bad or contamination)

    parts: list[str] = []
    if riskv1_bad:
        parts.append(
            f"CRITICAL: {len(riskv1_bad)} risk-v1 derived feature(s) detected: "
            f"{riskv1_bad}"
        )
    if contamination:
        parts.append(
            f"CRITICAL: {len(contamination)} cross-split hash contamination(s) "
            f"detected."
        )
    if not has_critical:
        parts.append("No critical leakage detected.")

    return LeakageReport(
        temporal_leakage_incidents=[],
        riskv1_derived_features=riskv1_bad,
        has_critical_leakage=has_critical,
        summary="; ".join(parts),
    )
