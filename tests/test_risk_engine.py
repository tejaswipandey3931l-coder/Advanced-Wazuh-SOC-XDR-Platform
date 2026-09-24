"""
Unit tests for Phase 5 Dynamic Risk Engine (risk-v1).
Verifies:
- Factor calculations (severity, correlation, volume, MITRE)
- CTI canonical aggregation, diminishing weights, and confidence precedence
- Adaptive weight redistribution (sum = 1.0 invariant)
- Volume ceiling (F_vol <= 90.0)
- Theoretical maximum base score (S_base <= 99.00)
- Half-life temporal decay
- Priority bands mapping
- Explanation and linear conservation invariant
- Monotonicity within stable availability states
"""

from datetime import datetime, timedelta, timezone
import pytest

from risk_engine.calculator import (
    calculate_risk_v1,
    calculate_temporal_decay,
    redistribute_weights,
)
from risk_engine.explainer import build_explanation
from risk_engine.models import FactorInputs, PriorityBand


def make_factor_inputs(**kwargs) -> FactorInputs:
    now = datetime.now(timezone.utc)
    defaults = {
        "wazuh_levels": [7],
        "incident_severity": "medium",
        "rule_confidence": 0.7,
        "rule_type": "sequence",
        "rule_priority": 50,
        "is_correlated": True,
        "alert_count": 5,
        "distinct_entities": 2,
        "mitre_tactics": ["execution", "persistence"],
        "observables_cti": [],
        "last_seen": now,
        "evidence_as_of": now,
        "evidence_version": 1,
        "evaluation_as_of": now,
    }
    defaults.update(kwargs)
    return FactorInputs(**defaults)


# ── Factor Calculations ───────────────────────────────────────────────────────


def test_severity_factor_calculation():
    # Only wazuh levels (16) and critical anchor (95.0)
    # Wazuh: (16 - 1) / 15 * 100 = 100.0. Blend: 0.60 * 100 + 0.40 * 95 = 98.0
    inp1 = make_factor_inputs(wazuh_levels=[16, 16], incident_severity="critical")
    res1 = calculate_risk_v1(inp1)
    assert res1["sub_scores"].severity == 98.0

    # Low wazuh levels (lvl 4 -> (4-1)/15*100 = 20.0), low anchor (25.0)
    # Blend: 0.60 * 20.0 + 0.40 * 25.0 = 12.0 + 10.0 = 22.0
    inp2 = make_factor_inputs(wazuh_levels=[4], incident_severity="low")
    res2 = calculate_risk_v1(inp2)
    assert res2["sub_scores"].severity == 22.0


def test_correlation_factor_calculation():
    # Correlated with sequence rule (multiplier 1.0)
    inp1 = make_factor_inputs(is_correlated=True, rule_type="sequence", rule_confidence=0.8, rule_priority=80)
    res1 = calculate_risk_v1(inp1)
    # 100.0 * (0.8 * 1.0 * 0.8) = 64.0
    assert res1["sub_scores"].correlation == pytest.approx(64.0)

    # Threshold rule (0.65 multiplier)
    inp2 = make_factor_inputs(is_correlated=True, rule_type="threshold", rule_confidence=0.8, rule_priority=80)
    res2 = calculate_risk_v1(inp2)
    assert res2["sub_scores"].correlation == pytest.approx(64.0 * 0.65)

    # Fallback un-correlated incident
    inp3 = make_factor_inputs(is_correlated=False)
    res3 = calculate_risk_v1(inp3)
    assert res3["sub_scores"].correlation == 40.0


def test_volume_factor_cap_at_90():
    # Massive alert and entity counts
    inp = make_factor_inputs(alert_count=100000, distinct_entities=5000)
    res = calculate_risk_v1(inp)
    # Must strictly never exceed 90.0
    assert res["sub_scores"].volume <= 90.0
    assert res["sub_scores"].volume == 90.0

    # Minimal count (N=1, E=1)
    inp_min = make_factor_inputs(alert_count=1, distinct_entities=1)
    res_min = calculate_risk_v1(inp_min)
    assert res_min["sub_scores"].volume == pytest.approx(25.964, rel=1e-3)


def test_mitre_factor_calculation():
    # 0 tactics -> unobserved
    inp0 = make_factor_inputs(mitre_tactics=[])
    res0 = calculate_risk_v1(inp0)
    assert res0["sub_scores"].mitre_coverage == 0.0
    assert res0["mitre_observed"] is False

    # 3 tactics: execution (40), persistence (50), privilege escalation (55)
    # max_weight = 55.0 + 5.0 * (3 - 1) = 65.0
    inp3 = make_factor_inputs(mitre_tactics=["execution", "persistence", "privilege escalation"])
    res3 = calculate_risk_v1(inp3)
    assert res3["sub_scores"].mitre_coverage == 65.0
    assert res3["mitre_observed"] is True

    # High impact tactics
    inp_hi = make_factor_inputs(mitre_tactics=["impact", "exfiltration", "command and control"])
    res_hi = calculate_risk_v1(inp_hi)
    # max is impact (95) + 5*(2) = 105 -> capped at 100.0
    assert res_hi["sub_scores"].mitre_coverage == 100.0


# ── CTI Resolution & Diminishing Weights ──────────────────────────────────────


def test_cti_confidence_precedence():
    # Provider confidence should take precedence over heuristic and legacy
    cti_record = {
        "verdict": "malicious",
        "provider_confidence": 0.9,
        "derived_heuristic_confidence": 0.6,
        "confidence": 0.4,
    }
    inp = make_factor_inputs(observables_cti=[cti_record])
    res = calculate_risk_v1(inp)
    assert res["sub_scores"].cti == pytest.approx(90.0)

    # If provider confidence missing, derived heuristic takes precedence
    cti_record2 = {
        "verdict": "malicious",
        "provider_confidence": None,
        "derived_heuristic_confidence": 0.7,
        "confidence": 0.4,
    }
    inp2 = make_factor_inputs(observables_cti=[cti_record2])
    res2 = calculate_risk_v1(inp2)
    assert res2["sub_scores"].cti == pytest.approx(70.0)

    # If all absent, C = 0.0 -> score 0.0
    cti_record3 = {
        "verdict": "malicious",
        "provider_confidence": None,
        "derived_heuristic_confidence": None,
        "confidence": None,
    }
    inp3 = make_factor_inputs(observables_cti=[cti_record3])
    res3 = calculate_risk_v1(inp3)
    assert res3["sub_scores"].cti == 0.0


def test_cti_verdicts_numeric_behavior():
    # Suspicious with C=0.8 -> 50 * 0.8 = 40.0
    inp_susp = make_factor_inputs(observables_cti=[{"verdict": "suspicious", "provider_confidence": 0.8}])
    assert calculate_risk_v1(inp_susp)["sub_scores"].cti == pytest.approx(40.0)

    # Conflict -> fixed 75.0
    inp_conflict = make_factor_inputs(observables_cti=[{"verdict": "conflict"}])
    assert calculate_risk_v1(inp_conflict)["sub_scores"].cti == pytest.approx(75.0)

    # Unknown and not_found -> neutral 0.0
    inp_unk = make_factor_inputs(observables_cti=[{"verdict": "unknown"}])
    assert calculate_risk_v1(inp_unk)["sub_scores"].cti == 0.0

    inp_nf = make_factor_inputs(observables_cti=[{"verdict": "not_found"}])
    assert calculate_risk_v1(inp_nf)["sub_scores"].cti == 0.0


def test_cti_confirmed_clean_negative_mitigation():
    inp_clean = make_factor_inputs(observables_cti=[{"verdict": "benign"}])
    res = calculate_risk_v1(inp_clean)
    assert res["clean_mitigation"] == 15.0
    assert res["sub_scores"].cti == 0.0


def test_cti_diminishing_weights_aggregation():
    # Primary: Malicious (C=0.6 -> 60.0)
    # Secondary: Suspicious (C=0.8 -> 40.0)
    # f_cti = min(100.0, 60.0 + 40.0 / (2^1)) = 60.0 + 20.0 = 80.0
    inp = make_factor_inputs(
        observables_cti=[
            {"ioc_type": "ip", "ioc_value": "1.2.3.4", "verdict": "malicious", "provider_confidence": 0.6},
            {"ioc_type": "domain", "ioc_value": "bad.com", "verdict": "suspicious", "provider_confidence": 0.8},
        ]
    )
    res = calculate_risk_v1(inp)
    assert res["sub_scores"].cti == pytest.approx(80.0)


# ── Weight Redistribution & Invariants ────────────────────────────────────────


def test_weight_redistribution_all_available():
    inp = make_factor_inputs(
        mitre_tactics=["execution"],
        observables_cti=[{"verdict": "suspicious", "provider_confidence": 0.5}],
    )
    res = calculate_risk_v1(inp)
    weights = res["effective_weights"]
    assert weights["severity"] == pytest.approx(0.30)
    assert weights["correlation"] == pytest.approx(0.25)
    assert weights["cti"] == pytest.approx(0.20)
    assert weights["volume"] == pytest.approx(0.10)
    assert weights["mitre_coverage"] == pytest.approx(0.15)
    assert sum(weights.values()) == pytest.approx(1.0)


def test_weight_redistribution_cti_and_mitre_unobserved():
    inp = make_factor_inputs(mitre_tactics=[], observables_cti=[])
    res = calculate_risk_v1(inp)
    weights = res["effective_weights"]
    # Redistributed: sev = 0.30 + 0.10 + 0.075 = 0.475
    # corr = 0.25 + 0.10 + 0.075 = 0.425
    # vol = 0.10
    assert weights["cti"] == 0.0
    assert weights["mitre_coverage"] == 0.0
    assert weights["severity"] == 0.475
    assert weights["correlation"] == 0.425
    assert weights["volume"] == 0.10
    assert sum(weights.values()) == pytest.approx(1.0)


def test_theoretical_maximum_base_score():
    # Maximum inputs: all factors 100, volume 90
    inp = make_factor_inputs(
        wazuh_levels=[16],
        incident_severity="critical",
        rule_confidence=1.0,
        rule_type="sequence",
        rule_priority=100,
        alert_count=100000,
        distinct_entities=10000,
        mitre_tactics=["impact", "exfiltration"],
        observables_cti=[{"verdict": "malicious", "provider_confidence": 1.0}],
    )
    res = calculate_risk_v1(inp)
    # Base score should never exceed 99.0
    assert res["base_score"] <= 99.0


# ── Temporal Decay ────────────────────────────────────────────────────────────


def test_temporal_decay_half_life():
    now = datetime.now(timezone.utc)

    # dt = 0 -> decay = 1.0
    assert calculate_temporal_decay(now, now) == 1.0

    # dt = 1 half-life (86400s) -> min_decay + (1 - min_decay)*0.5 = 0.25 + 0.75*0.5 = 0.625
    assert calculate_temporal_decay(now + timedelta(seconds=86400), now) == pytest.approx(0.625)

    # dt = 2 half-lives (172800s) -> 0.25 + 0.75*0.25 = 0.4375
    assert calculate_temporal_decay(now + timedelta(seconds=172800), now) == pytest.approx(0.4375)

    # dt -> infinity -> min_decay (0.25)
    assert calculate_temporal_decay(now + timedelta(days=100), now) == 0.25

    # negative dt -> 1.0
    assert calculate_temporal_decay(now - timedelta(hours=10), now) == 1.0


# ── Priority Bands ────────────────────────────────────────────────────────────


def test_priority_bands_mapping():
    now = datetime.now(timezone.utc)

    # Critical: >= 80.0
    inp_crit = make_factor_inputs(
        wazuh_levels=[16],
        incident_severity="critical",
        rule_confidence=1.0,
        rule_type="sequence",
        rule_priority=100,
        alert_count=50,
        distinct_entities=10,
        mitre_tactics=["impact", "exfiltration", "command and control"],
        observables_cti=[{"verdict": "malicious", "provider_confidence": 1.0}],
    )
    res_crit = calculate_risk_v1(inp_crit)
    assert res_crit["overall_score"] >= 80.0
    assert res_crit["priority_band"] == PriorityBand.CRITICAL
    assert res_crit["priority_band"].value == "CRITICAL"

    # Informational: < 20.0
    inp_info = make_factor_inputs(
        wazuh_levels=[1],
        incident_severity="low",
        is_correlated=False,
        alert_count=1,
        distinct_entities=1,
        mitre_tactics=[],
        observables_cti=[],
        last_seen=now,
        evaluation_as_of=now + timedelta(days=30),  # full decay
    )
    res_info = calculate_risk_v1(inp_info)
    assert res_info["overall_score"] < 20.0
    assert res_info["priority_band"] == PriorityBand.INFORMATIONAL
    assert res_info["priority_band"].value == "INFORMATIONAL"


# ── Linear Conservation Invariant & Explanation ───────────────────────────────


def test_linear_conservation_invariant():
    inp = make_factor_inputs(
        wazuh_levels=[10, 12],
        incident_severity="high",
        rule_confidence=0.85,
        rule_type="sequence",
        rule_priority=75,
        alert_count=20,
        distinct_entities=4,
        mitre_tactics=["execution", "discovery"],
        observables_cti=[
            {"verdict": "malicious", "provider_confidence": 0.8},
            {"verdict": "benign"},
        ],
    )
    calc_res = calculate_risk_v1(inp)
    exp = build_explanation(calc_res, incident_id="test-incident", calculated_at=datetime.now(timezone.utc))

    # Invariant: sum(contributions) - M_clean == base_score
    c = exp.contributions
    sum_contrib = c.severity + c.correlation + c.cti + c.volume + c.mitre_coverage
    m_clean = exp.mitigations.get("confirmed_clean_mitigation", 0.0)

    computed_base = max(0.0, min(99.0, sum_contrib - m_clean))
    assert abs(computed_base - exp.base_score) < 1e-4
    assert exp.conservation_verified is True


# ── Monotonicity Within Stable Availability ───────────────────────────────────


def test_monotonicity_within_stable_availability():
    base_cti = [{"verdict": "suspicious", "provider_confidence": 0.5}]
    inp_low = make_factor_inputs(
        wazuh_levels=[6],
        incident_severity="low",
        alert_count=2,
        mitre_tactics=["execution"],
        observables_cti=base_cti,
    )
    inp_high = make_factor_inputs(
        wazuh_levels=[14],
        incident_severity="critical",
        alert_count=20,
        mitre_tactics=["execution", "persistence", "privilege escalation"],
        observables_cti=base_cti,
    )

    res_low = calculate_risk_v1(inp_low)
    res_high = calculate_risk_v1(inp_high)

    assert res_high["overall_score"] > res_low["overall_score"]
    assert res_high["base_score"] > res_low["base_score"]
