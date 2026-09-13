"""
Reproducible performance benchmark for Phase 3 Event Correlation Engine.

Measures separately:
  1. Tier 1: Pure In-Memory CorrelationEngine (throughput, p50, p95, p99)
  2. Tier 2: Redis Window State Store (ZSET window updates and evaluation latency)
  3. Tier 3: PostgreSQL Incident Persistence (savepoint, deduplication, evidence linkage)
  4. Tier 4: End-to-End Pipeline (Raw alert -> Normalizer -> CorrelationEngine -> PostgreSQL)

Usage:
  .venv/bin/python experiments/benchmark_correlation.py [--events 2000]
"""

from __future__ import annotations

import argparse
import asyncio
import json
import math
from pathlib import Path
import statistics
import sys
import time
from datetime import datetime, timezone, timedelta
from uuid import uuid4

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import logging
import structlog
structlog.configure(wrapper_class=structlog.make_filtering_bound_logger(logging.CRITICAL))

from backend.app.config import get_settings
from backend.app.database import get_db
from backend.app.models.raw_alert import RawAlert
from backend.app.models.normalized_event import NormalizedEvent
from backend.app.schemas.wazuh import RawAlertItem
from normalizer.wazuh_normalizer import EventNormalizer
from correlation.engine import CorrelationEngine
from correlation.rules import RuleRegistry
from correlation.state import InMemoryWindowStateStore, RedisWindowStateStore
from correlation.service import CorrelationService


def calculate_percentiles(latencies_us: list[float]) -> dict[str, float]:
    sorted_lat = sorted(latencies_us)
    p50 = statistics.median(sorted_lat)
    p95_idx = int(math.ceil(0.95 * len(sorted_lat))) - 1
    p99_idx = int(math.ceil(0.99 * len(sorted_lat))) - 1
    mean = statistics.mean(sorted_lat)
    return {
        "mean_us": mean,
        "p50_us": p50,
        "p95_us": sorted_lat[p95_idx],
        "p99_us": sorted_lat[p99_idx],
        "min_us": sorted_lat[0],
        "max_us": sorted_lat[-1],
    }


async def benchmark_tier1_in_memory(event_count: int = 5000, warmup: int = 500) -> dict[str, float]:
    """Tier 1: Pure In-Memory CorrelationEngine."""
    registry = RuleRegistry()
    registry.load_defaults()
    store = InMemoryWindowStateStore()
    engine = CorrelationEngine(registry=registry, state_store=store)

    now = datetime.now(timezone.utc) - timedelta(seconds=event_count + warmup + 10)
    # Warmup
    for i in range(warmup):
        await engine.evaluate_event(
            event_id=uuid4(),
            event_timestamp=now + timedelta(milliseconds=i),
            event_dict={"event_type": "authentication_failed", "src_ip": "10.0.0.1", "auth_result": "failure"},
        )

    # Measured run
    latencies_ns: list[int] = []
    t_start = time.perf_counter()

    for i in range(event_count):
        eid = uuid4()
        ts = now + timedelta(milliseconds=warmup + i)
        ip = f"10.0.0.{(i % 20) + 1}"
        edict = {"event_type": "authentication_failed", "src_ip": ip, "auth_result": "failure"}

        t0 = time.perf_counter_ns()
        await engine.evaluate_event(event_id=eid, event_timestamp=ts, event_dict=edict)
        t1 = time.perf_counter_ns()
        latencies_ns.append(t1 - t0)

    total_sec = time.perf_counter() - t_start
    latencies_us = [ns / 1000.0 for ns in latencies_ns]
    stats = calculate_percentiles(latencies_us)
    stats["throughput_eps"] = event_count / total_sec
    stats["total_sec"] = total_sec
    stats["event_count"] = event_count
    return stats


async def benchmark_tier2_redis_store(event_count: int = 1000, warmup: int = 100) -> dict[str, float]:
    """Tier 2: RedisWindowStateStore evaluation."""
    settings = get_settings()
    store = RedisWindowStateStore(redis_url=settings.soc_redis_url)
    healthy = await store.check_health()
    if not healthy:
        return {"error": "Redis unavailable"}

    registry = RuleRegistry()
    registry.load_defaults()
    engine = CorrelationEngine(registry=registry, state_store=store)

    now = datetime.now(timezone.utc) - timedelta(seconds=event_count + warmup + 10)
    test_run_id = uuid4().hex[:6]

    # Warmup
    for i in range(warmup):
        await engine.evaluate_event(
            event_id=uuid4(),
            event_timestamp=now + timedelta(milliseconds=i),
            event_dict={"event_type": "authentication_failed", "src_ip": f"172.16.1.{test_run_id}", "auth_result": "failure"},
        )

    latencies_ns: list[int] = []
    t_start = time.perf_counter()

    for i in range(event_count):
        eid = uuid4()
        ts = now + timedelta(milliseconds=warmup + i)
        ip = f"172.16.{(i % 10) + 1}.{test_run_id}"
        edict = {"event_type": "authentication_failed", "src_ip": ip, "auth_result": "failure"}

        t0 = time.perf_counter_ns()
        await engine.evaluate_event(event_id=eid, event_timestamp=ts, event_dict=edict)
        t1 = time.perf_counter_ns()
        latencies_ns.append(t1 - t0)

    total_sec = time.perf_counter() - t_start
    await store.close()

    latencies_us = [ns / 1000.0 for ns in latencies_ns]
    stats = calculate_percentiles(latencies_us)
    stats["throughput_eps"] = event_count / total_sec
    stats["total_sec"] = total_sec
    stats["event_count"] = event_count
    return stats


async def benchmark_tier3_postgres_persistence(incident_count: int = 200) -> dict[str, float]:
    """Tier 3: PostgreSQL CorrelationService persistence and evidence linkage."""
    registry = RuleRegistry()
    registry.load_defaults()
    store = InMemoryWindowStateStore()
    engine = CorrelationEngine(registry=registry, state_store=store)
    service = CorrelationService(engine=engine)

    now = datetime.now(timezone.utc) - timedelta(seconds=incident_count + 10)
    latencies_ns: list[int] = []
    t_start = time.perf_counter()

    async for db in get_db():
        for i in range(incident_count):
            # Create a raw alert and normalized event
            raw = RawAlert(
                wazuh_index_id=f"bench-p3-{uuid4().hex}",
                raw_json={"bench": True, "idx": i},
                is_normalized=True,
            )
            db.add(raw)
            await db.flush()

            evt = NormalizedEvent(
                raw_alert_id=raw.id,
                event_type="authentication_failed",
                event_category="authentication",
                severity=5,
                rule_id="5710",
                source_type="wazuh_agent",
                src_ip=f"192.0.2.{i % 254 + 1}",
                auth_result="failure",
                event_timestamp=now + timedelta(seconds=i),
            )
            db.add(evt)
            await db.flush()

            t0 = time.perf_counter_ns()
            # Feed 5 events to trigger brute force and persist incident
            incidents = await service.process_normalized_event(db, evt)
            await db.commit()
            t1 = time.perf_counter_ns()

            latencies_ns.append(t1 - t0)
        break

    total_sec = time.perf_counter() - t_start
    latencies_ms = [ns / 1_000_000.0 for ns in latencies_ns]
    sorted_lat = sorted(latencies_ms)
    p50 = statistics.median(sorted_lat)
    p95_idx = int(math.ceil(0.95 * len(sorted_lat))) - 1
    p99_idx = int(math.ceil(0.99 * len(sorted_lat))) - 1

    return {
        "event_count": incident_count,
        "total_sec": total_sec,
        "throughput_eps": incident_count / total_sec,
        "mean_ms": statistics.mean(sorted_lat),
        "p50_ms": p50,
        "p95_ms": sorted_lat[p95_idx],
        "p99_ms": sorted_lat[p99_idx],
        "min_ms": sorted_lat[0],
        "max_ms": sorted_lat[-1],
    }


async def benchmark_tier4_end_to_end(event_count: int = 100) -> dict[str, float]:
    """Tier 4: End-to-end pipeline (RawAlertItem -> Normalizer -> Engine -> Persistence)."""
    settings = get_settings()
    store = RedisWindowStateStore(redis_url=settings.soc_redis_url)
    registry = RuleRegistry()
    registry.load_defaults()
    engine = CorrelationEngine(registry=registry, state_store=store)
    service = CorrelationService(engine=engine)
    normalizer = EventNormalizer()

    fixtures_path = PROJECT_ROOT / "tests" / "fixtures" / "wazuh_alerts_samples.json"
    with open(fixtures_path, "r", encoding="utf-8") as f:
        fixtures = json.load(f)

    sample_raw = fixtures["rule_5710_sshd_failed_login"]
    latencies_ns: list[int] = []
    t_start = time.perf_counter()

    async for db in get_db():
        for i in range(event_count):
            item = RawAlertItem(**sample_raw)
            item.id = f"bench-e2e-{uuid4().hex}"

            t0 = time.perf_counter_ns()
            # 1. Normalize
            norm = normalizer.normalize_alert(item)

            # 2. Persist Raw & Normalized
            raw = RawAlert(
                wazuh_index_id=item.id,
                raw_json=item.raw,
                is_normalized=True,
            )
            db.add(raw)
            await db.flush()

            evt = NormalizedEvent(
                id=norm.event_id,
                raw_alert_id=raw.id,
                event_type=norm.event_type,
                event_category=norm.event_category,
                severity=norm.severity,
                rule_id=norm.rule_id,
                source_type=norm.source_type,
                src_ip=norm.src_ip or f"192.168.1.{(i % 5) + 1}",
                auth_result=norm.auth_result,
                event_timestamp=norm.event_timestamp,
            )
            db.add(evt)
            await db.flush()

            # 3. Correlate and persist incident
            await service.process_normalized_event(db, evt)
            await db.commit()
            t1 = time.perf_counter_ns()

            latencies_ns.append(t1 - t0)
        break

    await store.close()
    total_sec = time.perf_counter() - t_start
    latencies_ms = [ns / 1_000_000.0 for ns in latencies_ns]
    sorted_lat = sorted(latencies_ms)
    p50 = statistics.median(sorted_lat)
    p95_idx = int(math.ceil(0.95 * len(sorted_lat))) - 1
    p99_idx = int(math.ceil(0.99 * len(sorted_lat))) - 1

    return {
        "event_count": event_count,
        "total_sec": total_sec,
        "throughput_eps": event_count / total_sec,
        "mean_ms": statistics.mean(sorted_lat),
        "p50_ms": p50,
        "p95_ms": sorted_lat[p95_idx],
        "p99_ms": sorted_lat[p99_idx],
        "min_ms": sorted_lat[0],
        "max_ms": sorted_lat[-1],
    }


async def main():
    parser = argparse.ArgumentParser(description="Phase 3 Multi-Tier Benchmark")
    parser.add_argument("--tier1-events", type=int, default=5000)
    parser.add_argument("--tier2-events", type=int, default=1000)
    parser.add_argument("--tier3-events", type=int, default=200)
    parser.add_argument("--tier4-events", type=int, default=100)
    args = parser.parse_args()

    print("=" * 70)
    print("PHASE 3: MULTI-TIER CORRELATION ENGINE BENCHMARK")
    print("=" * 70)

    print(f"\n[TIER 1] Pure In-Memory CorrelationEngine ({args.tier1_events} events):")
    t1 = await benchmark_tier1_in_memory(args.tier1_events)
    print(f"  Throughput: {t1['throughput_eps']:.1f} events/sec")
    print(f"  Latency:    mean={t1['mean_us']:.2f}µs | p50={t1['p50_us']:.2f}µs | p95={t1['p95_us']:.2f}µs | p99={t1['p99_us']:.2f}µs")

    print(f"\n[TIER 2] Redis Window State Store ({args.tier2_events} events):")
    t2 = await benchmark_tier2_redis_store(args.tier2_events)
    if "error" in t2:
        print(f"  Error: {t2['error']}")
    else:
        print(f"  Throughput: {t2['throughput_eps']:.1f} events/sec")
        print(f"  Latency:    mean={t2['mean_us']:.2f}µs | p50={t2['p50_us']:.2f}µs | p95={t2['p95_us']:.2f}µs | p99={t2['p99_us']:.2f}µs")

    print(f"\n[TIER 3] PostgreSQL Incident Persistence ({args.tier3_events} operations):")
    t3 = await benchmark_tier3_postgres_persistence(args.tier3_events)
    print(f"  Throughput: {t3['throughput_eps']:.1f} ops/sec")
    print(f"  Latency:    mean={t3['mean_ms']:.2f}ms | p50={t3['p50_ms']:.2f}ms | p95={t3['p95_ms']:.2f}ms | p99={t3['p99_ms']:.2f}ms")

    print(f"\n[TIER 4] End-to-End Pipeline ({args.tier4_events} events):")
    t4 = await benchmark_tier4_end_to_end(args.tier4_events)
    print(f"  Throughput: {t4['throughput_eps']:.1f} events/sec")
    print(f"  Latency:    mean={t4['mean_ms']:.2f}ms | p50={t4['p50_ms']:.2f}ms | p95={t4['p95_ms']:.2f}ms | p99={t4['p99_ms']:.2f}ms")
    print("=" * 70)


if __name__ == "__main__":
    asyncio.run(main())
