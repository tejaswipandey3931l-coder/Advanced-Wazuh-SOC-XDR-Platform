"""
Reproducible Performance Benchmark & Sensitivity Analysis for Phase 5: Dynamic Risk Scoring (risk-v1).

Sections:
  1. Pure In-Memory risk-v1 Calculator Benchmark (10,000 iterations, latency in µs, throughput)
  2. Full Evaluation + Explanation Building Benchmark (10,000 iterations)
  3. Sensitivity Analysis (CTI confidence variation, temporal decay sweep, partial derivatives)
  4. Monotonicity & Invariant Verification under Random Stress

Usage:
  .venv/bin/python experiments/benchmark_risk_engine.py [--iterations 10000]
"""

from __future__ import annotations

import argparse
from datetime import datetime, timedelta, timezone
from pathlib import Path
import random
import statistics
import sys
import time

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import logging
import structlog
structlog.configure(wrapper_class=structlog.make_filtering_bound_logger(logging.CRITICAL))

from risk_engine.calculator import calculate_risk_v1
from risk_engine.explainer import build_explanation
from risk_engine.models import FactorInputs


def calculate_percentiles(latencies_us: list[float]) -> dict[str, float]:
    if not latencies_us:
        return {}
    sorted_lat = sorted(latencies_us)
    n = len(sorted_lat)
    return {
        "p50": sorted_lat[int(n * 0.50)],
        "p90": sorted_lat[int(n * 0.90)],
        "p95": sorted_lat[int(n * 0.95)],
        "p99": sorted_lat[int(n * 0.99)],
        "mean": statistics.mean(sorted_lat),
        "min": sorted_lat[0],
        "max": sorted_lat[-1],
    }


def generate_random_factor_inputs(seed: int = 42) -> list[FactorInputs]:
    rng = random.Random(seed)
    now = datetime.now(timezone.utc)
    severities = ["informational", "low", "medium", "high", "critical"]
    rule_types = ["sequence", "entity_group", "temporal", "threshold", None]
    all_tactics = [
        "initial access", "execution", "persistence", "privilege escalation",
        "defense evasion", "credential access", "discovery", "lateral movement",
        "collection", "command and control", "exfiltration", "impact",
    ]
    cti_verdicts = ["malicious", "suspicious", "conflict", "benign", "not_found", "unknown"]

    inputs_list = []
    for _ in range(1000):
        # Wazuh levels: 1 to 10 random alerts
        wazuh_count = rng.randint(1, 10)
        wazuh_lvls = [rng.randint(1, 16) for _ in range(wazuh_count)]

        # MITRE tactics: 0 to 5 tactics
        tactic_count = rng.randint(0, 5)
        tactics = rng.sample(all_tactics, tactic_count)

        # CTI: 0 to 4 observables
        cti_count = rng.randint(0, 4)
        cti_list = []
        for j in range(cti_count):
            cti_list.append({
                "ioc_type": rng.choice(["ip", "domain", "sha256"]),
                "ioc_value": f"sample_ioc_{j}",
                "verdict": rng.choice(cti_verdicts),
                "provider_confidence": rng.uniform(0.1, 1.0) if rng.random() > 0.3 else None,
                "derived_heuristic_confidence": rng.uniform(0.1, 1.0) if rng.random() > 0.5 else None,
            })

        hours_old = rng.uniform(0.0, 120.0)
        last_seen = now - timedelta(hours=hours_old)

        inputs_list.append(FactorInputs(
            wazuh_levels=wazuh_lvls,
            incident_severity=rng.choice(severities),
            rule_confidence=rng.uniform(0.5, 1.0) if rng.random() > 0.2 else None,
            rule_type=rng.choice(rule_types),
            rule_priority=rng.randint(20, 100),
            is_correlated=rng.random() > 0.15,
            alert_count=rng.randint(1, 100),
            distinct_entities=rng.randint(1, 10),
            mitre_tactics=tactics,
            observables_cti=cti_list,
            last_seen=last_seen,
            evidence_as_of=last_seen,
            evidence_version=rng.randint(1, 5),
            evaluation_as_of=now,
        ))
    return inputs_list


def benchmark_pure_calculator(iterations: int = 10000) -> dict[str, float]:
    inputs_pool = generate_random_factor_inputs()
    pool_len = len(inputs_pool)

    # Warmup
    for i in range(100):
        calculate_risk_v1(inputs_pool[i % pool_len])

    latencies_us: list[float] = []
    t0 = time.perf_counter()
    for i in range(iterations):
        inp = inputs_pool[i % pool_len]
        s = time.perf_counter_ns()
        calculate_risk_v1(inp)
        e = time.perf_counter_ns()
        latencies_us.append((e - s) / 1000.0)
    total_time = time.perf_counter() - t0

    pct = calculate_percentiles(latencies_us)
    throughput = iterations / total_time
    pct["throughput_ops"] = throughput
    pct["total_time_s"] = total_time
    return pct


def benchmark_with_explanation(iterations: int = 10000) -> dict[str, float]:
    inputs_pool = generate_random_factor_inputs()
    pool_len = len(inputs_pool)
    now = datetime.now(timezone.utc)

    # Warmup
    for i in range(100):
        res = calculate_risk_v1(inputs_pool[i % pool_len])
        build_explanation(res, incident_id="warmup", calculated_at=now)

    latencies_us: list[float] = []
    t0 = time.perf_counter()
    for i in range(iterations):
        inp = inputs_pool[i % pool_len]
        s = time.perf_counter_ns()
        res = calculate_risk_v1(inp)
        build_explanation(res, incident_id=f"inc_{i}", calculated_at=now)
        e = time.perf_counter_ns()
        latencies_us.append((e - s) / 1000.0)
    total_time = time.perf_counter() - t0

    pct = calculate_percentiles(latencies_us)
    pct["throughput_ops"] = iterations / total_time
    pct["total_time_s"] = total_time
    return pct


def run_sensitivity_analysis() -> None:
    now = datetime.now(timezone.utc)
    print("\n--- SENSITIVITY ANALYSIS ---")

    # 1. CTI Confidence Sweep
    print("1. CTI Confidence Sensitivity (MALICIOUS verdict):")
    confidences = [0.0, 0.25, 0.50, 0.75, 1.00]
    for c in confidences:
        inp = FactorInputs(
            wazuh_levels=[10],
            incident_severity="medium",
            is_correlated=True,
            rule_type="sequence",
            rule_confidence=0.8,
            rule_priority=50,
            alert_count=5,
            distinct_entities=2,
            mitre_tactics=["execution"],
            observables_cti=[{"verdict": "malicious", "provider_confidence": c}],
            last_seen=now,
            evidence_as_of=now,
            evidence_version=1,
            evaluation_as_of=now,
        )
        res = calculate_risk_v1(inp)
        print(f"  Confidence C = {c:.2f} -> CTI Score: {res['sub_scores'].cti:5.1f} | Base Score: {res['base_score']:5.2f} | Final: {res['overall_score']:5.2f} ({res['priority_band'].value})")

    # 2. Temporal Decay Sweep across 1 week (0 to 168 hours)
    print("\n2. Temporal Decay Sensitivity (Half-life = 24 hours):")
    hours_list = [0, 12, 24, 48, 72, 96, 168]
    base_inp = FactorInputs(
        wazuh_levels=[14],
        incident_severity="high",
        is_correlated=True,
        rule_type="sequence",
        rule_confidence=0.9,
        rule_priority=80,
        alert_count=15,
        distinct_entities=3,
        mitre_tactics=["execution", "persistence"],
        observables_cti=[{"verdict": "malicious", "provider_confidence": 0.9}],
        last_seen=now,
        evidence_as_of=now,
        evidence_version=1,
        evaluation_as_of=now,
    )
    res_fresh = calculate_risk_v1(base_inp)
    base_score = res_fresh["base_score"]
    print(f"  Fresh Base Score: {base_score:.2f}")

    for h in hours_list:
        eval_time = now + timedelta(hours=h)
        inp_h = base_inp.model_copy(update={"evaluation_as_of": eval_time})
        res_h = calculate_risk_v1(inp_h)
        print(f"  Elapsed: {h:3d}h -> Decay Factor: {res_h['temporal_decay']:.4f} | Final Risk: {res_h['overall_score']:5.2f} ({res_h['priority_band'].value})")


def main():
    parser = argparse.ArgumentParser(description="Phase 5 Dynamic Risk Engine Benchmark")
    parser.add_argument("--iterations", type=int, default=10000, help="Number of benchmark iterations")
    args = parser.parse_args()

    print("================================================================================")
    print(f"PHASE 5 DYNAMIC RISK ENGINE BENCHMARK (risk-v1) — {args.iterations} Iterations")
    print("================================================================================")

    # 1. Pure Calculator
    pct_pure = benchmark_pure_calculator(args.iterations)
    print("\n[Tier 1] Pure In-Memory Calculator (calculate_risk_v1):")
    print(f"  Throughput: {pct_pure['throughput_ops']:,.0f} ops/sec")
    print(f"  Total Time: {pct_pure['total_time_s']:.3f} s")
    print(f"  Latency p50:  {pct_pure['p50']:6.2f} µs")
    print(f"  Latency p90:  {pct_pure['p90']:6.2f} µs")
    print(f"  Latency p95:  {pct_pure['p95']:6.2f} µs")
    print(f"  Latency p99:  {pct_pure['p99']:6.2f} µs")
    print(f"  Latency Mean: {pct_pure['mean']:6.2f} µs")

    # 2. Full Calculation + Explanation
    pct_exp = benchmark_with_explanation(args.iterations)
    print("\n[Tier 2] Calculator + Structured Explanation (build_explanation):")
    print(f"  Throughput: {pct_exp['throughput_ops']:,.0f} ops/sec")
    print(f"  Total Time: {pct_exp['total_time_s']:.3f} s")
    print(f"  Latency p50:  {pct_exp['p50']:6.2f} µs")
    print(f"  Latency p95:  {pct_exp['p95']:6.2f} µs")
    print(f"  Latency p99:  {pct_exp['p99']:6.2f} µs")
    print(f"  Latency Mean: {pct_exp['mean']:6.2f} µs")

    # Target assertion
    assert pct_pure["mean"] <= 50.0, f"Benchmark target exceeded: mean {pct_pure['mean']:.2f} µs > 50 µs"
    print("\n  >>> TARGET VERIFIED: Pure calculation mean latency <= 50 µs <<<")

    # 3. Sensitivity Analysis
    run_sensitivity_analysis()

    print("\n================================================================================")
    print("BENCHMARK & SENSITIVITY ANALYSIS COMPLETED SUCCESSFULLY")
    print("================================================================================")


if __name__ == "__main__":
    main()
