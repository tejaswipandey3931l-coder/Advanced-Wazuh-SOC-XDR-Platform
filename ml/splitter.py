"""
Phase 6 — Chronological train / validation / test splitting.

Split Strategy
--------------
Splitting is ALWAYS chronological (by incident created_at).  Random
splitting is prohibited to prevent temporal leakage.

The test set is FROZEN after construction and may never be used for
model selection, hyperparameter tuning, or calibration.

Default proportions
-------------------
  Train      : earliest 70 % of the timeline
  Validation : next 15 %
  Test       : newest 15 %

All proportions are configurable.

Campaign grouping
-----------------
The Incident schema is inspected for a ``campaign_id`` column.  If the
column exists and is reliably non-null, all incidents from the same
campaign are assigned to the same split.

IMPLEMENTATION NOTE: the ``incidents`` table does NOT currently have a
``campaign_id`` column.  This module falls back to hash-based grouping
(exact-duplicate deduplication) as documented.

Split manifest
--------------
After splitting, a JSON manifest is produced with:
  - Split boundaries (created_at range for each split)
  - Incident counts
  - Per-class distributions
  - SHA-256 hashes of the feature sets
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any

from .constants import PRIORITY_CLASS_ORDER


# campaign_id availability flag (inspected from the real schema).
# Set to True ONLY if the incidents table has a reliable campaign_id column.
CAMPAIGN_ID_AVAILABLE: bool = False  # VERIFIED: not in current schema.


@dataclass
class SplitResult:
    """Container for the three chronological splits."""

    train: list[dict] = field(default_factory=list)
    val: list[dict] = field(default_factory=list)
    test: list[dict] = field(default_factory=list)

    @property
    def train_hashes(self) -> set[str]:
        return {inc["feature_hash"] for inc in self.train}

    @property
    def val_hashes(self) -> set[str]:
        return {inc["feature_hash"] for inc in self.val}

    @property
    def test_hashes(self) -> set[str]:
        return {inc["feature_hash"] for inc in self.test}


@dataclass
class SplitManifest:
    """Serialisable manifest recording the complete split metadata."""

    split_strategy: str = "chronological"
    campaign_id_used: bool = False
    train_start: str = ""
    train_end: str = ""
    val_start: str = ""
    val_end: str = ""
    test_start: str = ""
    test_end: str = ""
    train_count: int = 0
    val_count: int = 0
    test_count: int = 0
    train_class_distribution: dict[str, int] = field(default_factory=dict)
    val_class_distribution: dict[str, int] = field(default_factory=dict)
    test_class_distribution: dict[str, int] = field(default_factory=dict)
    train_hash_fingerprint: str = ""
    val_hash_fingerprint: str = ""
    test_hash_fingerprint: str = ""
    created_at_utc: str = ""

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(asdict(self), indent=indent, default=str)


def chronological_split(
    incidents: list[dict],
    train_fraction: float = 0.70,
    val_fraction: float = 0.15,
) -> SplitResult:
    """
    Split incidents chronologically into train / validation / test sets.

    Parameters
    ----------
    incidents:
        Deduplicated list of incident dicts.  Each must contain:
          - ``created_at`` (datetime) – used for sorting.
          - ``feature_hash`` (str)    – for contamination checking.
          - ``priority_band`` (str)   – for class distribution stats.
          - ``incident_id`` (str)
    train_fraction:
        Fraction of the chronological timeline assigned to training.
    val_fraction:
        Fraction assigned to validation.  Test gets the remainder.

    Returns
    -------
    SplitResult
        Three non-overlapping splits.

    Raises
    ------
    ValueError
        If fractions do not sum to ≤ 1.0.
    """
    if train_fraction + val_fraction >= 1.0:
        raise ValueError(
            f"train_fraction ({train_fraction}) + val_fraction ({val_fraction}) "
            f"must be < 1.0."
        )

    if not incidents:
        return SplitResult()

    # Sort chronologically by created_at (ascending).
    sorted_incs = sorted(incidents, key=lambda x: x["created_at"])

    n = len(sorted_incs)
    train_end_idx = max(1, int(n * train_fraction))
    val_end_idx = max(train_end_idx + 1, int(n * (train_fraction + val_fraction)))
    # Ensure val_end_idx does not exceed n - 1 (reserve at least one for test).
    val_end_idx = min(val_end_idx, n - 1)

    return SplitResult(
        train=sorted_incs[:train_end_idx],
        val=sorted_incs[train_end_idx:val_end_idx],
        test=sorted_incs[val_end_idx:],
    )


def _class_distribution(incidents: list[dict]) -> dict[str, int]:
    """Count per-class occurrences in a split."""
    dist: dict[str, int] = {cls: 0 for cls in PRIORITY_CLASS_ORDER}
    for inc in incidents:
        band = inc.get("priority_band", "")
        if band in dist:
            dist[band] += 1
    return dist


def _hash_fingerprint(incidents: list[dict]) -> str:
    """Stable SHA-256 fingerprint over the sorted set of feature hashes."""
    hashes = sorted(inc.get("feature_hash", "") for inc in incidents)
    payload = "\n".join(hashes)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _ts(incidents: list[dict], key: str) -> str:
    """Extract and format a min/max created_at from an incident list."""
    timestamps = [inc["created_at"] for inc in incidents if "created_at" in inc]
    if not timestamps:
        return ""
    val = min(timestamps) if key == "min" else max(timestamps)
    if isinstance(val, datetime):
        return val.isoformat()
    return str(val)


def build_split_manifest(result: SplitResult) -> SplitManifest:
    """
    Build a serialisable SplitManifest from a SplitResult.

    Parameters
    ----------
    result:
        Output of chronological_split().

    Returns
    -------
    SplitManifest
    """
    return SplitManifest(
        split_strategy="chronological",
        campaign_id_used=CAMPAIGN_ID_AVAILABLE,
        train_start=_ts(result.train, "min"),
        train_end=_ts(result.train, "max"),
        val_start=_ts(result.val, "min"),
        val_end=_ts(result.val, "max"),
        test_start=_ts(result.test, "min"),
        test_end=_ts(result.test, "max"),
        train_count=len(result.train),
        val_count=len(result.val),
        test_count=len(result.test),
        train_class_distribution=_class_distribution(result.train),
        val_class_distribution=_class_distribution(result.val),
        test_class_distribution=_class_distribution(result.test),
        train_hash_fingerprint=_hash_fingerprint(result.train),
        val_hash_fingerprint=_hash_fingerprint(result.val),
        test_hash_fingerprint=_hash_fingerprint(result.test),
        created_at_utc=datetime.now(timezone.utc).isoformat(),
    )
