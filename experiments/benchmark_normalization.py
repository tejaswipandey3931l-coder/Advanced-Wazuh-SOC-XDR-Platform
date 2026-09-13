"""
Reproducible performance benchmark for Phase 2 EventNormalizer.

Measures:
  - p50 latency
  - p95 latency
  - p99 latency
  - Mean latency
  - Throughput (events / second)

Usage:
  .venv/bin/python experiments/benchmark_normalization.py [--events 5000]
"""

from __future__ import annotations

import argparse
import json
import math
from pathlib import Path
import statistics
import sys
import time

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from backend.app.schemas.wazuh import RawAlertItem
from normalizer.wazuh_normalizer import EventNormalizer

FIXTURES_PATH = Path(__file__).parent.parent / "tests" / "fixtures" / "wazuh_alerts_samples.json"


def run_benchmark(event_count: int = 5000, warmup_count: int = 500) -> dict[str, float]:
    with open(FIXTURES_PATH, "r", encoding="utf-8") as f:
        fixtures = json.load(f)

    # Use valid fixture samples
    valid_keys = [
        "rule_502_server_started",
        "rule_5710_sshd_failed_login",
        "rule_5715_sshd_success_login",
        "rule_550_syscheck_modified",
        "rule_554_syscheck_added",
        "sca_policy_check",
    ]
    sample_items = [RawAlertItem(**fixtures[k]) for k in valid_keys]

    normalizer = EventNormalizer()

    # Warmup
    for i in range(warmup_count):
        item = sample_items[i % len(sample_items)]
        normalizer.normalize_alert(item)

    # Measured runs
    latencies_ns: list[int] = []
    start_total = time.perf_counter()

    for i in range(event_count):
        item = sample_items[i % len(sample_items)]
        t0 = time.perf_counter_ns()
        normalizer.normalize_alert(item)
        t1 = time.perf_counter_ns()
        latencies_ns.append(t1 - t0)

    total_elapsed = time.perf_counter() - start_total
    latencies_us = [ns / 1000.0 for ns in latencies_ns]
    latencies_us.sort()

    p50 = statistics.median(latencies_us)
    p95_idx = int(math.ceil(0.95 * len(latencies_us))) - 1
    p99_idx = int(math.ceil(0.99 * len(latencies_us))) - 1
    p95 = latencies_us[p95_idx]
    p99 = latencies_us[p99_idx]
    mean = statistics.mean(latencies_us)
    events_per_sec = event_count / total_elapsed

    return {
        "event_count": float(event_count),
        "total_elapsed_sec": total_elapsed,
        "events_per_second": events_per_sec,
        "mean_latency_us": mean,
        "p50_latency_us": p50,
        "p95_latency_us": p95,
        "p99_latency_us": p99,
        "min_latency_us": latencies_us[0],
        "max_latency_us": latencies_us[-1],
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Normalizer Performance Benchmark")
    parser.add_argument("--events", type=int, default=5000, help="Number of events to benchmark")
    parser.add_argument("--warmup", type=int, default=500, help="Number of warmup iterations")
    args = parser.parse_args()

    print(f"=== Running Normalization Benchmark ({args.events} events, {args.warmup} warmup) ===")
    results = run_benchmark(event_count=args.events, warmup_count=args.warmup)

    print("\n--- Benchmark Results ---")
    print(f"Total events processed: {int(results['event_count'])}")
    print(f"Total elapsed time:     {results['total_elapsed_sec']:.4f} seconds")
    print(f"Throughput:             {results['events_per_second']:.2f} events/second")
    print(f"Mean latency:           {results['mean_latency_us']:.2f} µs")
    print(f"p50 latency:            {results['p50_latency_us']:.2f} µs")
    print(f"p95 latency:            {results['p95_latency_us']:.2f} µs")
    print(f"p99 latency:            {results['p99_latency_us']:.2f} µs")
    print(f"Min latency:            {results['min_latency_us']:.2f} µs")
    print(f"Max latency:            {results['max_latency_us']:.2f} µs")
