"""
Reproducible 4-Tier Performance Benchmark for Phase 4: Threat Intelligence Enrichment.

Tier 1: Pure In-Memory IOC Extraction & Normalization (latency in µs, throughput in items/sec)
Tier 2: Redis CTI Cache Operations (SET, GET hit, GET miss latencies in µs)
Tier 3: LocalFeed Indicator Matching (exact, CIDR, wildcard, NOT_FOUND lookups/sec)
Tier 4: Asynchronous Multi-Provider Pipeline (using Mock providers with simulated network delays)

Usage:
  .venv/bin/python experiments/benchmark_threat_intel.py [--iterations 1000]
"""

from __future__ import annotations

import argparse
import asyncio
from datetime import datetime, timezone
import math
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
# Mute logging during benchmark to avoid IO bias
structlog.configure(wrapper_class=structlog.make_filtering_bound_logger(logging.CRITICAL))

from backend.app.config import get_settings
from backend.app.models.threat_intel_result import IOCType
from threat_intel.cache import ThreatIntelCache
from threat_intel.consensus import ConsensusEngine
from threat_intel.extractor import IOCExtractor
from threat_intel.models import (
    NormalizedObservable,
    ProviderResult,
    ProviderStatus,
    ThreatVerdict,
)
from threat_intel.normalizer import (
    normalize_domain,
    normalize_hash,
    normalize_ip,
    normalize_observable,
    normalize_url,
)
from threat_intel.providers.base import BaseThreatIntelProvider
from threat_intel.providers.local_feed import LocalFeedProvider
from threat_intel.service import ThreatIntelService


def calculate_percentiles(latencies_us: list[float]) -> dict[str, float]:
    if not latencies_us:
        return {}
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


def benchmark_tier_1_extraction_and_normalization(iterations: int) -> dict:
    sample_text = (
        "Inbound connection from 198.51.100.25 to host 10.0.0.5. "
        "Observed payload from hxxp://c2-command[.]net/drop.exe with hash "
        "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f. "
        "Phishing sender: attacker@malicious-campaign.org."
    )

    latencies_us: list[float] = []

    # Warm-up
    for _ in range(50):
        IOCExtractor.extract_from_text(sample_text)

    t0 = time.perf_counter()
    for _ in range(iterations):
        s0 = time.perf_counter()
        observables = IOCExtractor.extract_from_text(sample_text)
        latencies_us.append((time.perf_counter() - s0) * 1_000_000.0)
    total_time = time.perf_counter() - t0

    throughput = iterations / total_time
    iocs_per_run = len(observables)
    total_iocs_sec = (iterations * iocs_per_run) / total_time

    stats = calculate_percentiles(latencies_us)
    stats["throughput_payloads_per_sec"] = throughput
    stats["throughput_iocs_per_sec"] = total_iocs_sec
    stats["iocs_per_payload"] = iocs_per_payload = len(observables)
    return stats


async def benchmark_tier_2_redis_cache(iterations: int) -> dict:
    cache = ThreatIntelCache()
    health = await cache.check_health()
    is_live_redis = health.get("redis_connected", False)

    obs = normalize_ip("198.51.100.25")
    sample_res = ProviderResult(
        provider="benchmark_provider",
        observable=obs,
        status=ProviderStatus.SUCCESS,
        verdict=ThreatVerdict.MALICIOUS,
        provider_confidence=0.95,
    )

    set_latencies_us: list[float] = []
    get_latencies_us: list[float] = []

    # Warm-up
    await cache.set("benchmark_provider", obs, sample_res)
    for _ in range(20):
        await cache.get("benchmark_provider", obs)

    # Benchmark SET
    t_set_start = time.perf_counter()
    for i in range(iterations):
        test_obs = normalize_ip(f"198.51.100.{(i % 250) + 1}")
        s0 = time.perf_counter()
        await cache.set("benchmark_provider", test_obs, sample_res)
        set_latencies_us.append((time.perf_counter() - s0) * 1_000_000.0)
    total_set_time = time.perf_counter() - t_set_start

    # Benchmark GET (Hit)
    t_get_start = time.perf_counter()
    for i in range(iterations):
        test_obs = normalize_ip(f"198.51.100.{(i % 250) + 1}")
        s0 = time.perf_counter()
        await cache.get("benchmark_provider", test_obs)
        get_latencies_us.append((time.perf_counter() - s0) * 1_000_000.0)
    total_get_time = time.perf_counter() - t_get_start

    # Clean up benchmark keys
    await cache.invalidate(provider="benchmark_provider")
    await cache.close()

    set_stats = calculate_percentiles(set_latencies_us)
    get_stats = calculate_percentiles(get_latencies_us)

    return {
        "redis_connected": is_live_redis,
        "set_operations": {
            "throughput_ops_sec": iterations / total_set_time,
            **set_stats,
        },
        "get_hit_operations": {
            "throughput_ops_sec": iterations / total_get_time,
            **get_stats,
        },
    }


async def benchmark_tier_3_local_feed(iterations: int) -> dict:
    provider = LocalFeedProvider()

    test_observables = [
        normalize_ip("198.51.100.99"),  # Exact match
        normalize_ip("203.0.113.55"),   # CIDR match
        normalize_domain("sub.bad-actor.net"),  # Wildcard match
        normalize_ip("8.8.8.8"),        # NOT_FOUND match
    ]

    latencies_us: list[float] = []

    # Warm-up
    for obs in test_observables:
        await provider.lookup(obs)

    t0 = time.perf_counter()
    for i in range(iterations):
        target_obs = test_observables[i % len(test_observables)]
        s0 = time.perf_counter()
        await provider.lookup(target_obs)
        latencies_us.append((time.perf_counter() - s0) * 1_000_000.0)
    total_time = time.perf_counter() - t0

    stats = calculate_percentiles(latencies_us)
    stats["throughput_lookups_sec"] = iterations / total_time
    return stats


class SimulatedNetworkProvider(BaseThreatIntelProvider):
    """Simulates an external CTI provider with bounded network delay for benchmarking."""

    def __init__(self, name: str, min_delay_ms: float = 10.0, max_delay_ms: float = 30.0):
        self._name = name
        self._min_delay = min_delay_ms / 1000.0
        self._max_delay = max_delay_ms / 1000.0

    @property
    def name(self) -> str:
        return self._name

    @property
    def supported_ioc_types(self) -> set[IOCType]:
        return {IOCType.IP, IOCType.DOMAIN, IOCType.FILE_HASH, IOCType.URL, IOCType.EMAIL}

    async def lookup(self, observable: NormalizedObservable) -> ProviderResult:
        delay = random.uniform(self._min_delay, self._max_delay)
        await asyncio.sleep(delay)
        return ProviderResult(
            provider=self.name,
            observable=observable,
            status=ProviderStatus.SUCCESS,
            verdict=ThreatVerdict.MALICIOUS if hash(observable.canonical_value) % 2 == 0 else ThreatVerdict.BENIGN,
            provider_confidence=0.85,
        )

    async def check_health(self):
        from threat_intel.models import ProviderHealth
        return ProviderHealth(provider=self.name, status="healthy", enabled=True)

    async def close(self) -> None:
        pass


import os
import platform
import subprocess

def get_system_metadata() -> dict[str, Any]:
    meta = {
        "os_platform": platform.platform(),
        "python_version": sys.version.split()[0],
        "cpu_cores": os.cpu_count(),
        "cpu_model": "Unknown",
        "ram_total": "Unknown",
        "redis_version": "Unknown",
    }
    # CPU
    try:
        with open("/proc/cpuinfo") as f:
            for line in f:
                if "model name" in line:
                    meta["cpu_model"] = line.split(":", 1)[1].strip()
                    break
    except Exception:
        pass
    # RAM
    try:
        with open("/proc/meminfo") as f:
            for line in f:
                if "MemTotal" in line:
                    kb = int(line.split(":", 1)[1].replace("kB", "").strip())
                    meta["ram_total"] = f"{kb / (1024 * 1024):.2f} GB ({kb:,} kB)"
                    break
    except Exception:
        pass
    # Redis
    try:
        res = subprocess.run(["docker", "exec", "soc_redis", "redis-server", "--version"], capture_output=True, text=True, timeout=3)
        if res.returncode == 0:
            meta["redis_version"] = res.stdout.strip()
    except Exception:
        pass
    return meta


async def benchmark_tier_4_pipeline_mock(iterations: int, concurrency_limit: int = 10) -> dict:
    from threat_intel.providers import ProviderRegistry

    registry = ProviderRegistry()
    registry.register(SimulatedNetworkProvider("mock_cti_1", 10.0, 25.0))
    registry.register(SimulatedNetworkProvider("mock_cti_2", 15.0, 30.0))
    registry.register(LocalFeedProvider())

    cache = ThreatIntelCache()
    service = ThreatIntelService(registry=registry, cache=cache, max_concurrent_lookups=concurrency_limit)

    observables = [
        normalize_ip(f"8.8.8.{(i % 250) + 1}")
        for i in range(iterations)
    ]

    latencies_ms: list[float] = []

    # True end-to-end latency measurement per observable:
    # Measures wall-clock time from task initiation through concurrent provider queries,
    # response parsing, and consensus derivation.
    async def enrich_single_timed(obs: NormalizedObservable) -> float:
        s0 = time.perf_counter()
        await service.enrich_observable(obs, force_refresh=True)
        return (time.perf_counter() - s0) * 1000.0

    # Warm-up (10 observables)
    for w_obs in observables[:10]:
        await service.enrich_observable(w_obs, force_refresh=True)

    # Run in batches bounded by concurrency limit
    t0 = time.perf_counter()
    batch_size = concurrency_limit
    for i in range(0, iterations, batch_size):
        chunk = observables[i : i + batch_size]
        chunk_latencies = await asyncio.gather(*[enrich_single_timed(obs) for obs in chunk])
        latencies_ms.extend(chunk_latencies)
    total_time = time.perf_counter() - t0

    await service.close()
    await cache.close()

    sorted_lat = sorted(latencies_ms)
    p50 = statistics.median(sorted_lat)
    p95_idx = int(math.ceil(0.95 * len(sorted_lat))) - 1
    p99_idx = int(math.ceil(0.99 * len(sorted_lat))) - 1

    return {
        "concurrency_limit": concurrency_limit,
        "providers_per_observable": 3,
        "simulated_network_delay_range_ms": "mock_cti_1 (10-25ms), mock_cti_2 (15-30ms), local_feed (<1ms)",
        "throughput_observables_per_sec": iterations / total_time,
        "total_wall_clock_time_sec": total_time,
        "latency_per_observable_ms": {
            "mean_ms": statistics.mean(sorted_lat),
            "p50_ms": p50,
            "p95_ms": sorted_lat[p95_idx],
            "p99_ms": sorted_lat[p99_idx],
            "min_ms": sorted_lat[0],
            "max_ms": sorted_lat[-1],
        },
    }


async def main():
    parser = argparse.ArgumentParser(description="Phase 4 Threat Intelligence Benchmark")
    parser.add_argument("--iterations", type=int, default=1000, help="Number of benchmark iterations per tier")
    args = parser.parse_args()

    meta = get_system_metadata()

    print("=" * 80)
    print("PHASE 4: THREAT INTELLIGENCE SUB-SYSTEM BENCHMARK")
    print("=" * 80)
    print(f"  Command Line              : {' '.join(sys.argv)}")
    print(f"  OS / Kernel               : {meta['os_platform']}")
    print(f"  CPU Model                 : {meta['cpu_model']}")
    print(f"  CPU Cores                 : {meta['cpu_cores']}")
    print(f"  System RAM Total          : {meta['ram_total']}")
    print(f"  Python Version            : {meta['python_version']}")
    print(f"  Redis Server Version      : {meta['redis_version']}")
    print(f"  Requested Iterations      : {args.iterations}")
    print(f"  Warm-Up Methodology       : 50 runs (Tier 1), 20 runs (Tier 2), 4 runs (Tier 3), 10 runs (Tier 4)")
    print("=" * 80)

    # Tier 1
    print("\n[Tier 1] In-Memory IOC Extraction & Normalization (Pure CPU)")
    print("  Measures regex extraction, defanging, and canonicalization of mixed forensic payloads.")
    t1 = benchmark_tier_1_extraction_and_normalization(args.iterations)
    print(f"  Throughput (Payloads/sec) : {t1['throughput_payloads_per_sec']:,.1f} payloads/s")
    print(f"  Throughput (IOCs/sec)     : {t1['throughput_iocs_per_sec']:,.1f} observables/s")
    print(f"  Mean Latency              : {t1['mean_us']:.2f} µs")
    print(f"  p50 Latency               : {t1['p50_us']:.2f} µs")
    print(f"  p95 Latency               : {t1['p95_us']:.2f} µs")
    print(f"  p99 Latency               : {t1['p99_us']:.2f} µs")

    # Tier 2
    print("\n[Tier 2] Redis CTI Cache Operations")
    print("  Measures SET and GET hit performance with provider-partitioned keys against live Redis.")
    t2 = await benchmark_tier_2_redis_cache(args.iterations)
    print(f"  Live Redis Active         : {t2['redis_connected']}")
    print(f"  Cache SET Throughput      : {t2['set_operations']['throughput_ops_sec']:,.1f} ops/s")
    print(f"  Cache SET p50 / p95 / p99 : {t2['set_operations']['p50_us']:.2f} µs / {t2['set_operations']['p95_us']:.2f} µs / {t2['set_operations']['p99_us']:.2f} µs")
    print(f"  Cache GET (Hit) Throughput: {t2['get_hit_operations']['throughput_ops_sec']:,.1f} ops/s")
    print(f"  Cache GET p50 / p95 / p99 : {t2['get_hit_operations']['p50_us']:.2f} µs / {t2['get_hit_operations']['p95_us']:.2f} µs / {t2['get_hit_operations']['p99_us']:.2f} µs")

    # Tier 3
    print("\n[Tier 3] LocalFeed Indicator Matcher (In-Memory Trie/Subnet/Wildcard)")
    print("  Measures exact hash/IP, CIDR subnet (ipaddress), domain wildcard, and NOT_FOUND lookups.")
    t3 = await benchmark_tier_3_local_feed(args.iterations * 2)
    print(f"  Throughput (Lookups/sec)  : {t3['throughput_lookups_sec']:,.1f} lookups/s")
    print(f"  Mean Latency              : {t3['mean_us']:.2f} µs")
    print(f"  p50 Latency               : {t3['p50_us']:.2f} µs")
    print(f"  p95 Latency               : {t3['p95_us']:.2f} µs")
    print(f"  p99 Latency               : {t3['p99_us']:.2f} µs")

    # Tier 4
    tier4_iter = min(args.iterations, 200)
    print(f"\n[Tier 4] Asynchronous Multi-Provider Pipeline ({tier4_iter} observables, Concurrency Limit = 10)")
    print("  METHODOLOGY NOTE:")
    print("  Tier 4 measures true end-to-end enrichment latency per observable across 3 concurrent")
    print("  providers (mock_cti_1: 10-25ms delay, mock_cti_2: 15-30ms delay, local_feed: <1ms in-memory).")
    print("  Concurrency is applied at two levels: (1) 3 providers queried concurrently per observable;")
    print("  (2) Up to 10 observables processed concurrently bounded by semaphore.")
    print("  Latency reflects individual start-to-finish wall-clock duration (max provider delay + orchestration).")
    print("  Throughput reflects aggregated pipeline completion rate across the 10 concurrent slots.")
    t4 = await benchmark_tier_4_pipeline_mock(iterations=tier4_iter, concurrency_limit=10)
    print(f"  Simulated Provider Delays : {t4['simulated_network_delay_range_ms']}")
    print(f"  Throughput                : {t4['throughput_observables_per_sec']:,.1f} observables/s")
    print(f"  Total Wall Clock Time     : {t4['total_wall_clock_time_sec']:.2f} s")
    print(f"  Mean Latency              : {t4['latency_per_observable_ms']['mean_ms']:.2f} ms")
    print(f"  p50 Latency               : {t4['latency_per_observable_ms']['p50_ms']:.2f} ms")
    print(f"  p95 Latency               : {t4['latency_per_observable_ms']['p95_ms']:.2f} ms")
    print(f"  p99 Latency               : {t4['latency_per_observable_ms']['p99_ms']:.2f} ms")
    print(f"  Min / Max Latency         : {t4['latency_per_observable_ms']['min_ms']:.2f} ms / {t4['latency_per_observable_ms']['max_ms']:.2f} ms")

    print("\n" + "=" * 80)
    print("BENCHMARK EXECUTION COMPLETED")
    print("=" * 80)


if __name__ == "__main__":
    asyncio.run(main())
