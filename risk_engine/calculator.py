"""
Pure mathematical risk scoring engine for Phase 5 (risk-v1).

Zero database dependencies. Fully deterministic, bounded, and explainable.
"""

from __future__ import annotations

import math
from datetime import datetime
from typing import Any

from .models import ComponentScores, FactorInputs, PriorityBand

# Tactical weights for MITRE ATT&CK stages
MITRE_TACTIC_WEIGHTS: dict[str, float] = {
    "initial access": 30.0,
    "execution": 40.0,
    "persistence": 50.0,
    "privilege escalation": 55.0,
    "defense evasion": 60.0,
    "credential access": 65.0,
    "discovery": 45.0,
    "lateral movement": 70.0,
    "collection": 55.0,
    "command and control": 80.0,
    "exfiltration": 90.0,
    "impact": 95.0,
}

# Incident severity baseline anchors
SEVERITY_ANCHORS: dict[str, float] = {
    "informational": 10.0,
    "low": 25.0,
    "medium": 50.0,
    "high": 75.0,
    "critical": 95.0,
}

# Correlation rule type weights
CORRELATION_TYPE_WEIGHTS: dict[str, float] = {
    "sequence": 1.00,
    "entity_group": 0.85,
    "temporal": 0.70,
    "threshold": 0.65,
}


def map_priority_band(score: float) -> PriorityBand:
    """
    Deterministically maps final score to priority band.
    Brackets:
      [0.00, 20.00)  -> INFORMATIONAL
      [20.00, 40.00) -> LOW
      [40.00, 60.00) -> MEDIUM
      [60.00, 80.00) -> HIGH
      [80.00, 100.00] -> CRITICAL
    """
    clamped_score = max(0.0, min(100.0, float(score)))
    if clamped_score < 20.0:
        return PriorityBand.INFORMATIONAL
    if clamped_score < 40.0:
        return PriorityBand.LOW
    if clamped_score < 60.0:
        return PriorityBand.MEDIUM
    if clamped_score < 80.0:
        return PriorityBand.HIGH
    return PriorityBand.CRITICAL


def calculate_severity_factor(wazuh_levels: list[int], incident_severity: str) -> float:
    """
    Calculates F_sev in [0.0, 100.0].
    F_sev = 0.60 * (0.70 * max(l) + 0.30 * mean(l)) + 0.40 * Anchor(S_inc)
    where l = (L - 1) / 15 * 100.0
    """
    if wazuh_levels:
        normalized_levels = [
            max(0.0, min(100.0, (float(lvl) - 1.0) / 15.0 * 100.0))
            for lvl in wazuh_levels
        ]
        max_l = max(normalized_levels)
        mean_l = sum(normalized_levels) / len(normalized_levels)
        alert_part = 0.70 * max_l + 0.30 * mean_l
    else:
        alert_part = 0.0

    anchor = SEVERITY_ANCHORS.get(incident_severity.lower(), 50.0)
    raw_sev = 0.60 * alert_part + 0.40 * anchor
    return max(0.0, min(100.0, raw_sev))


def calculate_correlation_factor(
    rule_confidence: float | None,
    rule_type: str | None,
    rule_priority: int | None,
    is_correlated: bool = True,
) -> float:
    """
    Calculates F_corr in [0.0, 100.0].
    Consumes actual Phase 3 rule base_confidence.
    For unmatched single-alert incidents, returns fallback 40.0.
    """
    if not is_correlated or rule_type is None:
        return 40.0

    c_rule = 0.70 if rule_confidence is None else max(0.0, min(1.0, float(rule_confidence)))
    w_type = CORRELATION_TYPE_WEIGHTS.get(rule_type.lower(), 0.70)
    p_norm = 0.50 if rule_priority is None else max(0.0, min(1.0, float(rule_priority) / 100.0))

    raw_corr = 100.0 * (c_rule * w_type * p_norm)
    return max(0.0, min(100.0, raw_corr))


def calculate_volume_factor(alert_count: int, distinct_entities: int) -> float:
    """
    Calculates F_vol strictly capped at 90.0.
    F_vol = min(90.0, V_count(N) * D_entity)
    V_count(N) = 100 * (1 - 1 / (1 + ln(1 + N/2)))
    D_entity = min(1.25, 0.80 + 0.10 * min(E, 5))
    """
    n = max(1, int(alert_count))
    e = max(1, int(distinct_entities))

    v_count = 100.0 * (1.0 - (1.0 / (1.0 + math.log(1.0 + n / 2.0))))
    d_entity = min(1.25, 0.80 + 0.10 * min(e, 5))

    raw_vol = v_count * d_entity
    return max(0.0, min(90.0, raw_vol))


def calculate_mitre_factor(tactics: list[str]) -> tuple[float, bool]:
    """
    Calculates F_mitre in [0.0, 100.0].
    F_mitre = min(100.0, max(W_t) + 5.0 * (|T| - 1))
    Returns (score, is_observed).
    """
    canonical_tactics = set()
    for t in tactics:
        cleaned = t.strip().lower()
        if cleaned in MITRE_TACTIC_WEIGHTS:
            canonical_tactics.add(cleaned)
        else:
            # Handle possible "TA0001: Initial Access" formats
            for known, weight in MITRE_TACTIC_WEIGHTS.items():
                if known in cleaned:
                    canonical_tactics.add(known)
                    break

    if not canonical_tactics:
        return 0.0, False

    max_weight = max(MITRE_TACTIC_WEIGHTS[t] for t in canonical_tactics)
    count = len(canonical_tactics)
    score = min(100.0, max_weight + 5.0 * (count - 1))
    return max(0.0, min(100.0, score)), True


def resolve_observable_confidence(obs: dict[str, Any]) -> tuple[float, str]:
    """
    Resolves confidence according to strict precedence hierarchy:
    provider_native > derived_uncalibrated_heuristic > legacy_provider > unavailable (0.0).
    """
    native = obs.get("provider_confidence")
    if native is not None:
        return max(0.0, min(1.0, float(native))), "provider_native"

    heuristic = obs.get("derived_heuristic_confidence")
    if heuristic is not None:
        return max(0.0, min(1.0, float(heuristic))), "derived_heuristic"

    legacy = obs.get("confidence")
    if legacy is not None:
        return max(0.0, min(1.0, float(legacy))), "legacy_provider"

    return 0.0, "unavailable"


def calculate_cti_factor(observables_cti: list[dict[str, Any]]) -> tuple[float, bool, bool]:
    """
    Calculates F_cti in [0.0, 100.0] using deterministic canonical aggregation.
    Returns (f_cti, is_cti_observed, is_all_clean).
    """
    if not observables_cti:
        return 0.0, False, False

    is_cti_observed = True
    scored_observables = []
    clean_count = 0

    for obs in observables_cti:
        verdict = str(obs.get("verdict", "")).strip().lower()
        conf, _ = resolve_observable_confidence(obs)

        if verdict == "malicious":
            item_score = 100.0 * conf
        elif verdict == "suspicious":
            item_score = 50.0 * conf
        elif verdict == "conflict":
            item_score = 75.0
        elif verdict in ("benign", "confirmed_clean"):
            item_score = -25.0
            clean_count += 1
        elif verdict in ("not_found", "unknown"):
            item_score = 0.0
        else:
            item_score = 0.0

        ioc_type = str(obs.get("ioc_type", "")).strip().lower()
        ioc_val = str(obs.get("ioc_value", "")).strip()

        scored_observables.append({
            "ioc_type": ioc_type,
            "ioc_value": ioc_val,
            "verdict": verdict,
            "confidence": conf,
            "score": item_score,
        })

    is_all_clean = (clean_count == len(scored_observables) and clean_count > 0)

    # Filter positive contributors
    positive_contributors = [o for o in scored_observables if o["score"] > 0.0]

    if not positive_contributors:
        # All neutral or negative
        return 0.0, is_cti_observed, is_all_clean

    # Select primary anchor (highest score; tie-break: smallest (ioc_type, ioc_val))
    positive_contributors.sort(
        key=lambda x: (-x["score"], x["ioc_type"], x["ioc_value"])
    )
    primary = positive_contributors[0]
    s_max = primary["score"]

    secondary = positive_contributors[1:]
    # Sort remaining deterministically by canonical key (ioc_type, canonical_value)
    secondary.sort(key=lambda x: (x["ioc_type"], x["ioc_value"]))

    secondary_sum = 0.0
    for j, sec in enumerate(secondary, start=1):
        secondary_sum += sec["score"] / (2.0 ** j)

    f_cti = min(100.0, s_max + secondary_sum)
    return max(0.0, min(100.0, f_cti)), is_cti_observed, False


def redistribute_weights(cti_observed: bool, mitre_observed: bool) -> dict[str, float]:
    """
    Applies cumulative weight redistribution when CTI or MITRE are unavailable.
    Guarantees that effective weights sum to exactly 1.0.
    """
    w_sev = 0.30
    w_corr = 0.25
    w_cti = 0.20
    w_vol = 0.10
    w_mitre = 0.15

    if not cti_observed:
        w_sev += 0.10
        w_corr += 0.10
        w_cti = 0.0

    if not mitre_observed:
        w_sev += 0.075
        w_corr += 0.075
        w_mitre = 0.0

    weights = {
        "severity": round(w_sev, 6),
        "correlation": round(w_corr, 6),
        "cti": round(w_cti, 6),
        "volume": round(w_vol, 6),
        "mitre_coverage": round(w_mitre, 6),
    }

    assert abs(sum(weights.values()) - 1.0) < 1e-6, f"Weights must sum to 1.0, got {sum(weights.values())}"
    return weights


def calculate_temporal_decay(
    evaluation_as_of: datetime,
    last_seen: datetime,
    half_life_seconds: float = 86400.0,
    min_decay: float = 0.25,
) -> float:
    """
    Calculates temporal decay factor D(dt) in [min_decay, 1.0].
    D(dt) = min_decay + (1 - min_decay) * 2^(-dt / half_life)
    where dt = max(0, evaluation_as_of - last_seen)
    """
    dt_seconds = max(0.0, (evaluation_as_of - last_seen).total_seconds())
    decay = min_decay + (1.0 - min_decay) * math.pow(2.0, -dt_seconds / half_life_seconds)
    return max(min_decay, min(1.0, decay))


def synthesize_base_score(
    factor_scores: dict[str, float],
    weights: dict[str, float],
    is_all_clean: bool,
    clean_mitigation: float = 15.0,
) -> tuple[float, float]:
    """
    Synthesizes un-decayed base evidentiary score S_base in [0.0, 99.0].
    S_base = max(0.0, min(99.0, sum(w_k * F_k) - M_clean))
    Returns (base_score, mitigation_applied).
    """
    weighted_sum = sum(weights[k] * factor_scores[k] for k in weights)
    m_clean = clean_mitigation if is_all_clean else 0.0
    base_score = max(0.0, min(99.0, weighted_sum - m_clean))
    return base_score, m_clean


def calculate_final_score(base_score: float, decay: float) -> float:
    """
    Calculates final priority score R in [0.00, 100.00].
    R = round(min(100.0, max(0.0, base_score * decay)), 2)
    """
    return round(max(0.0, min(100.0, base_score * decay)), 2)


def calculate_risk_v1(inputs: FactorInputs) -> dict[str, Any]:
    """
    Main pure evaluation function for risk-v1.
    """
    # 1. Component Factors
    f_sev = calculate_severity_factor(inputs.wazuh_levels, inputs.incident_severity)
    f_corr = calculate_correlation_factor(
        inputs.rule_confidence, inputs.rule_type, inputs.rule_priority, inputs.is_correlated
    )
    f_vol = calculate_volume_factor(inputs.alert_count, inputs.distinct_entities)
    f_mitre, mitre_observed = calculate_mitre_factor(inputs.mitre_tactics)
    f_cti, cti_observed, is_all_clean = calculate_cti_factor(inputs.observables_cti)

    factor_scores = {
        "severity": f_sev,
        "correlation": f_corr,
        "cti": f_cti,
        "volume": f_vol,
        "mitre_coverage": f_mitre,
    }

    # 2. Cumulative Weight Redistribution
    effective_weights = redistribute_weights(cti_observed, mitre_observed)

    # 3. Base Score Synthesis
    base_score, m_clean = synthesize_base_score(factor_scores, effective_weights, is_all_clean)

    # 4. Temporal Decay
    temporal_decay = calculate_temporal_decay(inputs.evaluation_as_of, inputs.last_seen)

    # 5. Final Score & Band
    final_score = calculate_final_score(base_score, temporal_decay)
    priority_band = map_priority_band(final_score)

    # 6. Contributions for explainability
    contributions = {
        k: effective_weights[k] * factor_scores[k]
        for k in factor_scores
    }

    return {
        "overall_score": final_score,
        "priority_band": priority_band,
        "base_score": base_score,
        "temporal_decay": temporal_decay,
        "sub_scores": ComponentScores(
            severity=f_sev,
            correlation=f_corr,
            cti=f_cti,
            volume=f_vol,
            mitre_coverage=f_mitre,
        ),
        "effective_weights": effective_weights,
        "factors": factor_scores,
        "contributions": contributions,
        "clean_mitigation": m_clean,
        "is_all_clean": is_all_clean,
        "cti_observed": cti_observed,
        "mitre_observed": mitre_observed,
        "evidence_version": inputs.evidence_version,
        "evidence_as_of": inputs.evidence_as_of,
        "evaluation_as_of": inputs.evaluation_as_of,
    }
