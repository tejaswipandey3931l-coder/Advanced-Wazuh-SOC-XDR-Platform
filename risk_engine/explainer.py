"""
Structured explanation builder for Phase 5 (risk-v1).

Enforces the linear conservation invariant:
Sum(Contributions) - Mitigation == Base Score.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from .models import ComponentContributions, PriorityBand, RiskExplanation


def build_explanation(
    calc_result: dict[str, Any],
    incident_id: str | None = None,
    calculated_at: datetime | None = None,
) -> RiskExplanation:
    """
    Builds a structured RiskExplanation from pure calculator output,
    validating the linear conservation invariant.
    """
    contributions_dict = calc_result["contributions"]
    contributions = ComponentContributions(
        severity=round(contributions_dict["severity"], 4),
        correlation=round(contributions_dict["correlation"], 4),
        cti=round(contributions_dict["cti"], 4),
        volume=round(contributions_dict["volume"], 4),
        mitre_coverage=round(contributions_dict["mitre_coverage"], 4),
    )

    mitigations = {
        "clean_iocs": round(calc_result.get("clean_mitigation", 0.0), 4)
    }

    base_score = calc_result["base_score"]
    clean_mitigation = calc_result.get("clean_mitigation", 0.0)

    # Validate Linear Conservation Invariant
    sum_contrib = sum(contributions_dict.values())
    unclamped_net = sum_contrib - clean_mitigation
    expected_base = max(0.0, min(99.0, unclamped_net))
    conservation_diff = abs(expected_base - base_score)
    conservation_verified = conservation_diff < 1e-4

    # Generate Human-Readable Summary
    band: PriorityBand = calc_result["priority_band"]
    overall_score = calc_result["overall_score"]
    decay = calc_result["temporal_decay"]

    # Identify primary contributing driver
    sorted_contributors = sorted(
        contributions_dict.items(), key=lambda item: item[1], reverse=True
    )
    primary_factor, primary_val = sorted_contributors[0]

    factor_names = {
        "severity": "Wazuh alert severity",
        "correlation": "Correlation rule context",
        "cti": "Threat intelligence observables",
        "volume": "Alert volume & entity diversity",
        "mitre_coverage": "MITRE ATT&CK tactical coverage",
    }

    summary_parts = [
        f"{band.value.upper()} priority ({overall_score:.2f}/100.0) "
        f"primarily driven by {factor_names.get(primary_factor, primary_factor)} "
        f"(+{primary_val:.2f} pts)."
    ]

    if clean_mitigation > 0.0:
        summary_parts.append(f"Mitigated by confirmed clean observables (-{clean_mitigation:.1f} pts).")

    if decay < 0.999:
        summary_parts.append(f"Temporal decay active (factor: {decay:.3f}).")

    summary = " ".join(summary_parts)

    calc_time = calculated_at or datetime.now(timezone.utc)

    return RiskExplanation(
        incident_id=incident_id,
        evidence_as_of=calc_result["evidence_as_of"],
        evidence_version=calc_result["evidence_version"],
        evaluation_as_of=calc_result["evaluation_as_of"],
        calculated_at=calc_time,
        overall_score=overall_score,
        priority_band=band,
        base_score=round(base_score, 4),
        temporal_decay=round(decay, 4),
        contributions=contributions,
        mitigations=mitigations,
        weights_used=calc_result["effective_weights"],
        conservation_verified=conservation_verified,
        summary=summary,
    )
