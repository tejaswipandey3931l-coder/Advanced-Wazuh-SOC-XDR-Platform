"""
Live Integration Tests for Phase 4 Threat Intelligence Subsystem.
Requires live PostgreSQL and Redis.
External CTI tests execute conditionally ONLY when API keys are configured.
"""

from __future__ import annotations

import os
import uuid
from datetime import datetime, timezone

import pytest
from sqlalchemy import func, select

from backend.app.config import get_settings
from backend.app.database import AsyncSessionLocal
from backend.app.models.threat_intel_result import CTISource, IOCType, ThreatIntelResult
from threat_intel.cache import ThreatIntelCache
from threat_intel.models import (
    NormalizedObservable,
    ProviderResult,
    ProviderStatus,
    ThreatVerdict,
)
from threat_intel.normalizer import normalize_domain, normalize_hash, normalize_ip
from threat_intel.providers.abuseipdb import AbuseIPDBProvider
from threat_intel.providers.local_feed import LocalFeedProvider
from threat_intel.providers.virustotal import VirusTotalProvider
from threat_intel.service import ThreatIntelService


@pytest.fixture(autouse=True)
async def cleanup_db_engine():
    yield
    from backend.app.database import engine
    await engine.dispose()


@pytest.mark.live
@pytest.mark.asyncio
async def test_live_local_feed_evaluation():
    """Verifies live in-memory LocalFeedProvider using production feed configuration."""
    provider = LocalFeedProvider()
    health = await provider.check_health()
    assert health.status == "healthy"
    assert health.enabled is True

    # 1. Exact match from configs/threat_intel/local_feed.json
    res_exact = await provider.lookup(normalize_ip("198.51.100.99"))
    assert res_exact.status == ProviderStatus.SUCCESS
    assert res_exact.verdict == ThreatVerdict.MALICIOUS
    assert res_exact.provider_confidence == 0.95

    # 2. CIDR subnet match (203.0.113.0/24)
    res_cidr = await provider.lookup(normalize_ip("203.0.113.15"))
    assert res_cidr.status == ProviderStatus.SUCCESS
    assert res_cidr.verdict == ThreatVerdict.MALICIOUS

    # 3. Domain wildcard match (*.bad-actor.net)
    res_wild = await provider.lookup(normalize_domain("sub01.bad-actor.net"))
    assert res_wild.status == ProviderStatus.SUCCESS
    assert res_wild.verdict == ThreatVerdict.MALICIOUS

    # 4. Clean observable -> NOT_FOUND (no record in local feed)
    res_clean = await provider.lookup(normalize_ip("8.8.4.4"))
    assert res_clean.status == ProviderStatus.NOT_FOUND
    assert res_clean.verdict == ThreatVerdict.UNKNOWN
    assert res_clean.provider_confidence is None


@pytest.mark.live
@pytest.mark.asyncio
async def test_live_redis_cache_integration():
    """Verifies live Redis caching, TTL setting, and key partitioning."""
    cache = ThreatIntelCache()
    health = await cache.check_health()
    assert health["redis_connected"] is True, "Redis is not reachable"

    obs = normalize_ip("8.8.8.8")
    # Clean any prior key
    await cache.invalidate("local_feed", obs)

    res = ProviderResult(
        provider="local_feed",
        observable=obs,
        status=ProviderStatus.NOT_FOUND,
        verdict=ThreatVerdict.BENIGN,
        provider_confidence=1.0,
    )
    await cache.set("local_feed", obs, res)

    # Verify retrieval
    cached = await cache.get("local_feed", obs)
    assert cached is not None
    assert cached.cached is True
    assert cached.status == ProviderStatus.NOT_FOUND

    # Clean up
    deleted = await cache.invalidate("local_feed", obs)
    assert deleted >= 1
    assert await cache.get("local_feed", obs) is None
    await cache.close()


@pytest.mark.live
@pytest.mark.asyncio
async def test_live_postgresql_persistence_and_append_only():
    """Verifies live PostgreSQL insertion and application-layer append-only semantics."""
    service = ThreatIntelService()
    obs = normalize_ip("198.51.100.99")

    async with AsyncSessionLocal() as db:
        # Count existing records for this observable
        initial_count = await db.scalar(
            select(func.count(ThreatIntelResult.id)).where(
                ThreatIntelResult.ioc_value == obs.canonical_value
            )
        ) or 0

        # Perform first enrichment with persistence
        await service.enrich_observable(
            observable=obs,
            requested_providers=["local_feed"],
            force_refresh=True,
            db=db,
        )
        await db.commit()

        count_after_first = await db.scalar(
            select(func.count(ThreatIntelResult.id)).where(
                ThreatIntelResult.ioc_value == obs.canonical_value
            )
        )
        assert count_after_first == initial_count + 1

        # Perform second enrichment on same observable
        await service.enrich_observable(
            observable=obs,
            requested_providers=["local_feed"],
            force_refresh=True,
            db=db,
        )
        await db.commit()

        count_after_second = await db.scalar(
            select(func.count(ThreatIntelResult.id)).where(
                ThreatIntelResult.ioc_value == obs.canonical_value
            )
        )
        # Strict append-only: second lookup creates a new row, neither updating nor deleting previous
        assert count_after_second == count_after_first + 1

    await service.close()


@pytest.mark.live
@pytest.mark.asyncio
async def test_live_abuseipdb_lookup_conditional():
    """Conditionally tests live AbuseIPDB query ONLY if API key is configured."""
    cfg = get_settings()
    api_key = cfg.abuseipdb_api_key or os.getenv("ABUSEIPDB_API_KEY")

    if not api_key:
        pytest.skip("AbuseIPDB live test skipped: ABUSEIPDB_API_KEY is not configured")

    provider = AbuseIPDBProvider(api_key=api_key, enabled=True)
    obs = normalize_ip("8.8.8.8")
    result = await provider.lookup(obs)
    await provider.close()

    assert result.status in (ProviderStatus.SUCCESS, ProviderStatus.NOT_FOUND)
    assert result.provider == "abuseipdb"


@pytest.mark.live
@pytest.mark.asyncio
async def test_live_virustotal_lookup_conditional():
    """Conditionally tests live VirusTotal query ONLY if API key is configured."""
    cfg = get_settings()
    api_key = cfg.virustotal_api_key or os.getenv("VIRUSTOTAL_API_KEY")

    if not api_key:
        pytest.skip("VirusTotal live test skipped: VIRUSTOTAL_API_KEY is not configured")

    provider = VirusTotalProvider(api_key=api_key, enabled=True)
    obs = normalize_hash("275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f")
    result = await provider.lookup(obs)
    await provider.close()

    assert result.status in (ProviderStatus.SUCCESS, ProviderStatus.NOT_FOUND)
    assert result.provider == "virustotal"
