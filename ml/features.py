"""
Phase 6 — Deterministic, T_prediction-safe feature extraction.

Specification
-------------
All features are extracted from RAW evidence only.
NO risk-v1 derived values (risk_score, factor scores, weights, decay,
priority band, explanation) may be used as features in the primary
experiment.

T_prediction enforcement
------------------------
Every piece of evidence consumed by this module is verified to have
originated AT or BEFORE T_prediction.  Evidence timestamped AFTER
T_prediction is silently discarded so that the feature vector cannot
contain future information.

Feature dictionary (v1.0.0)
-----------------------------
Feature                 Type    Description
---------------------------------------------------------------------------------------
severity_wazuh          float   Incident severity normalised to [0.0, 1.0]:
                                informational=0.1, low=0.25, medium=0.5,
                                high=0.75, critical=0.95
alert_count_log         float   log1p(alert_count) – captures volume without
                                risk-v1's internal formula
corr_rule_type_*        float   One-hot: entity_group, temporal, sequence, unknown
corr_confidence         float   Correlation rule base_confidence [0, 1] (raw value)
cti_max_confidence      float   max(confidence) across CTI records ≤ T_prediction
ioc_count               float   Number of distinct IOC lookups ≤ T_prediction
mitre_tactic_count      float   Distinct MITRE tactics on incident
time_of_day_*           float   One-hot: night, morning, day, evening
day_of_week_*           float   One-hot: mon … sun
incident_age_minutes    float   max(0, T_prediction − incident.created_at) in minutes
"""

from __future__ import annotations

import math
from datetime import datetime, timezone
from typing import Any

from .constants import FEATURE_SCHEMA_VERSION

# ── Severity anchor mapping (normalised to [0, 1]) ────────────────────────
_SEVERITY_MAP: dict[str, float] = {
    "informational": 0.1,
    "low": 0.25,
    "medium": 0.5,
    "high": 0.75,
    "critical": 0.95,
}

# ── Correlation rule type one-hot columns ─────────────────────────────────
_CORR_RULE_TYPES: list[str] = ["entity_group", "temporal", "sequence"]

# ── Time-of-day buckets (UTC hour boundaries, inclusive start / exclusive end)
_TIME_OF_DAY_BUCKETS: list[tuple[str, int, int]] = [
    ("night", 0, 6),
    ("morning", 6, 12),
    ("day", 12, 18),
    ("evening", 18, 24),
]

# ── Day-of-week columns ───────────────────────────────────────────────────
_DOW_NAMES: list[str] = ["mon", "tue", "wed", "thu", "fri", "sat", "sun"]

# ── Feature column ordering (MUST remain stable across versions) ─────────
FEATURE_COLUMNS: list[str] = [
    "severity_wazuh",
    "alert_count_log",
    "corr_rule_type_entity_group",
    "corr_rule_type_temporal",
    "corr_rule_type_sequence",
    "corr_rule_type_unknown",
    "corr_confidence",
    "cti_max_confidence",
    "ioc_count",
    "mitre_tactic_count",
    "time_of_day_night",
    "time_of_day_morning",
    "time_of_day_day",
    "time_of_day_evening",
    "day_of_week_mon",
    "day_of_week_tue",
    "day_of_week_wed",
    "day_of_week_thu",
    "day_of_week_fri",
    "day_of_week_sat",
    "day_of_week_sun",
    "incident_age_minutes",
]


def compute_incident_age_minutes(
    created_at: datetime,
    t_prediction: datetime,
) -> float:
    """
    Compute incident age in minutes at the given logical prediction cutoff.

    Definition
    ----------
    incident_age_minutes = max(0, T_prediction - incident.created_at)

    Rules
    -----
    * T_prediction is the logical prediction/evidence cutoff, NOT the
      wall-clock time at which inference is performed.
    * The feature never uses information after T_prediction.
    * If created_at > T_prediction (future-created relative to prediction
      horizon), the result is 0.0 (clamped).
    * Both datetimes are converted to UTC before subtraction to avoid
      timezone arithmetic errors.

    Parameters
    ----------
    created_at:
        UTC datetime when the incident was created in the database.
    t_prediction:
        Logical evidence cutoff timestamp (UTC or tz-aware).

    Returns
    -------
    float
        Age in minutes, clamped to [0.0, ∞).
    """
    # Normalise to UTC to be safe.
    if created_at.tzinfo is None:
        created_at = created_at.replace(tzinfo=timezone.utc)
    if t_prediction.tzinfo is None:
        t_prediction = t_prediction.replace(tzinfo=timezone.utc)

    delta_seconds = (t_prediction - created_at).total_seconds()
    return max(0.0, delta_seconds / 60.0)


def extract_features(
    incident_id: str,
    created_at: datetime,
    severity: str,
    alert_count: int,
    correlation_rule_type: str | None,
    correlation_confidence: float | None,
    cti_records: list[dict[str, Any]],  # list of {"queried_at": datetime, "confidence": float}
    mitre_tactics: list[str],
    t_prediction: datetime,
) -> dict[str, float]:
    """
    Extract a deterministic, T_prediction-safe feature vector for one incident.

    All evidence timestamps are checked against t_prediction.  Any CTI record
    with queried_at > t_prediction is silently excluded (temporal leakage
    prevention).

    Parameters
    ----------
    incident_id:
        String incident UUID (for logging/audit only; not a feature).
    created_at:
        Incident creation timestamp from the database.
    severity:
        Incident severity string (e.g. "medium").
    alert_count:
        Total alert count associated with the incident.
    correlation_rule_type:
        Optional rule type string (e.g. "sequence").
    correlation_confidence:
        Optional rule base_confidence [0, 1].
    cti_records:
        List of CTI observation dicts.  Each must contain:
          - ``queried_at`` (datetime): when the CTI lookup was performed.
          - ``confidence`` (float | None): provider confidence [0, 1].
        Records with queried_at > t_prediction are excluded.
    mitre_tactics:
        List of MITRE tactic strings from the incident.
    t_prediction:
        Logical evidence cutoff.  No feature may encode information
        originating after this timestamp.

    Returns
    -------
    dict[str, float]
        Feature vector keyed by FEATURE_COLUMNS names.
    """
    # Normalise T_prediction to UTC.
    if t_prediction.tzinfo is None:
        t_prediction = t_prediction.replace(tzinfo=timezone.utc)

    fv: dict[str, float] = {}

    # 1. severity_wazuh: raw severity → normalised [0, 1].
    fv["severity_wazuh"] = _SEVERITY_MAP.get(severity.lower(), 0.5)

    # 2. alert_count_log: log1p(alert_count) – volume proxy independent of
    #    risk-v1's internal formula.
    fv["alert_count_log"] = math.log1p(max(0, int(alert_count)))

    # 3. Correlation rule type one-hot.
    rt = (correlation_rule_type or "").lower().strip()
    for rtype in _CORR_RULE_TYPES:
        fv[f"corr_rule_type_{rtype}"] = 1.0 if rt == rtype else 0.0
    fv["corr_rule_type_unknown"] = (
        1.0 if (rt == "" or rt not in _CORR_RULE_TYPES) else 0.0
    )

    # 4. corr_confidence: raw base_confidence [0, 1], missing → 0.0.
    fv["corr_confidence"] = float(
        max(0.0, min(1.0, correlation_confidence))
        if correlation_confidence is not None
        else 0.0
    )

    # 5. CTI features — filter to records at or before T_prediction.
    valid_cti = _filter_cti_by_t_prediction(cti_records, t_prediction)
    confidences = [
        float(r["confidence"])
        for r in valid_cti
        if r.get("confidence") is not None
    ]
    fv["cti_max_confidence"] = max(confidences) if confidences else 0.0
    fv["ioc_count"] = float(len(valid_cti))

    # 6. MITRE tactic count (already at T_prediction since incident-level).
    fv["mitre_tactic_count"] = float(len(set(t.strip().lower() for t in mitre_tactics)))

    # 7. Temporal features derived from incident.created_at.
    #    These describe when the incident was created; they do NOT encode
    #    any post-T_prediction information.
    norm_created = created_at
    if norm_created.tzinfo is None:
        norm_created = norm_created.replace(tzinfo=timezone.utc)
    hour_utc = norm_created.hour
    dow_utc = norm_created.weekday()  # 0=Monday … 6=Sunday

    for bucket_name, start_h, end_h in _TIME_OF_DAY_BUCKETS:
        fv[f"time_of_day_{bucket_name}"] = (
            1.0 if start_h <= hour_utc < end_h else 0.0
        )

    for idx, dow_name in enumerate(_DOW_NAMES):
        fv[f"day_of_week_{dow_name}"] = 1.0 if dow_utc == idx else 0.0

    # 8. incident_age_minutes: deterministic, T_prediction-safe.
    fv["incident_age_minutes"] = compute_incident_age_minutes(
        created_at=norm_created,
        t_prediction=t_prediction,
    )

    # Verify all declared columns are present.
    missing = [col for col in FEATURE_COLUMNS if col not in fv]
    if missing:
        raise RuntimeError(
            f"Feature extraction BUG: missing columns {missing} for "
            f"incident_id={incident_id!r}."
        )

    return fv


def feature_vector_as_list(feature_dict: dict[str, float]) -> list[float]:
    """
    Return the feature vector as an ordered list matching FEATURE_COLUMNS.

    Parameters
    ----------
    feature_dict:
        Output of ``extract_features()``.

    Returns
    -------
    list[float]
        Values in canonical FEATURE_COLUMNS order.
    """
    return [feature_dict[col] for col in FEATURE_COLUMNS]


def _filter_cti_by_t_prediction(
    cti_records: list[dict[str, Any]],
    t_prediction: datetime,
) -> list[dict[str, Any]]:
    """
    Exclude CTI records queried after T_prediction (temporal leakage guard).

    A CTI record is included if and only if:
        record["queried_at"] <= t_prediction

    Records missing ``queried_at`` are excluded (conservative policy).
    """
    valid: list[dict[str, Any]] = []
    for rec in cti_records:
        queried_at = rec.get("queried_at")
        if queried_at is None:
            continue
        if isinstance(queried_at, str):
            # Parse ISO-8601 if passed as string.
            queried_at = datetime.fromisoformat(queried_at)
        if queried_at.tzinfo is None:
            queried_at = queried_at.replace(tzinfo=timezone.utc)
        if queried_at <= t_prediction:
            valid.append(rec)
    return valid
