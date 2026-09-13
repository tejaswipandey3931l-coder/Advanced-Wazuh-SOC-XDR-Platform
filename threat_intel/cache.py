"""
Redis CTI Cache with provider-partitioned keys, tiered TTL policies,
and automatic in-memory fallback when Redis is unavailable.
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone
import json
import time
from typing import Any

from redis import asyncio as aioredis
from redis.exceptions import ConnectionError as RedisConnectionError, TimeoutError as RedisTimeoutError
import structlog

from backend.app.config import get_settings
from backend.app.models.threat_intel_result import IOCType
from threat_intel.models import (
    NormalizedObservable,
    ProviderResult,
    ProviderStatus,
    ThreatVerdict,
)

logger = structlog.get_logger(__name__)


class InMemoryCTICache:
    """In-memory cache with monotonic TTL expiration used as fallback when Redis is unavailable."""

    def __init__(self) -> None:
        # Key -> (ProviderResult, expire_monotonic_timestamp)
        self._store: dict[str, tuple[ProviderResult, float]] = {}
        self._lock = asyncio.Lock()

    async def get(self, key: str) -> ProviderResult | None:
        async with self._lock:
            if key not in self._store:
                return None
            res, expires_at = self._store[key]
            if time.monotonic() > expires_at:
                del self._store[key]
                return None
            # Return copy with cached=True
            res_copy = res.model_copy()
            res_copy.cached = True
            return res_copy

    async def set(self, key: str, result: ProviderResult, ttl_seconds: int) -> None:
        async with self._lock:
            self._store[key] = (result, time.monotonic() + ttl_seconds)

    async def invalidate(self, pattern: str | None = None) -> int:
        async with self._lock:
            if not pattern or pattern == "*":
                count = len(self._store)
                self._store.clear()
                return count

            # Simple prefix or exact match
            prefix = pattern.rstrip("*")
            keys_to_delete = [k for k in self._store if k.startswith(prefix)]
            for k in keys_to_delete:
                del self._store[k]
            return len(keys_to_delete)

    def size(self) -> int:
        return len(self._store)


class ThreatIntelCache:
    """
    Tiered CTI Cache:
    - Primary: Redis with provider-partitioned keys
    - Fallback: Local in-memory cache with monotonic TTLs
    - Expiration policies:
        Positive (malicious/suspicious): 24h
        Negative (clean/not_found): 2h
        Error / Rate-Limited: 2m
    """

    def __init__(self, redis_client: aioredis.Redis | None = None, redis_url: str | None = None) -> None:
        cfg = get_settings()
        self._redis_url = redis_url or cfg.soc_redis_url
        self._ttl_positive = cfg.ti_cache_ttl_positive
        self._ttl_negative = cfg.ti_cache_ttl_negative
        self._ttl_error = cfg.ti_cache_ttl_error

        self._redis = redis_client
        self._owns_redis = redis_client is None
        self._fallback = InMemoryCTICache()
        self._is_redis_degraded = False

    def _get_redis(self) -> aioredis.Redis:
        if self._redis is None:
            self._redis = aioredis.from_url(
                self._redis_url,
                encoding="utf-8",
                decode_responses=True,
                socket_timeout=2.0,
                socket_connect_timeout=2.0,
            )
        return self._redis

    @staticmethod
    def build_key(provider: str, observable: NormalizedObservable) -> str:
        """
        Builds provider-partitioned cache key:
        ti:cache:{provider}:{ioc_type}:{canonical_ioc_value}
        Guarantees that one provider's cached result can never be returned as another provider's result.
        """
        return f"ti:cache:{provider.lower()}:{observable.ioc_type.value}:{observable.canonical_value.lower()}"

    def calculate_ttl(self, result: ProviderResult) -> int:
        """Determines TTL based on verdict and status."""
        # Errors and rate limits get short error TTL (2m)
        if result.status in (
            ProviderStatus.RATE_LIMITED,
            ProviderStatus.TIMEOUT,
            ProviderStatus.NETWORK_ERROR,
            ProviderStatus.AUTH_ERROR,
        ):
            return self._ttl_error

        # Positive malicious / suspicious detections get 24h
        if result.verdict in (ThreatVerdict.MALICIOUS, ThreatVerdict.SUSPICIOUS):
            return self._ttl_positive

        # Clean / NOT_FOUND / Benign get 2h
        return self._ttl_negative

    async def get(self, provider: str, observable: NormalizedObservable) -> ProviderResult | None:
        """Retrieves cached result for an observable from Redis, with transparent fallback."""
        key = self.build_key(provider, observable)

        # Try Redis first
        try:
            r = self._get_redis()
            cached_data = await r.get(key)
            if cached_data:
                if self._is_redis_degraded:
                    logger.info("redis_cache_recovered", key=key)
                    self._is_redis_degraded = False

                res_dict = json.loads(cached_data)
                result = ProviderResult.model_validate(res_dict)
                result.cached = True
                return result

            # Redis returned None (cache miss)
            return None
        except (RedisConnectionError, RedisTimeoutError, OSError) as exc:
            if not self._is_redis_degraded:
                logger.warning("redis_cache_degraded_falling_back_to_memory", error=str(exc))
                self._is_redis_degraded = True
            return await self._fallback.get(key)
        except Exception as exc:
            logger.error("redis_cache_unexpected_error", error=str(exc))
            return await self._fallback.get(key)

    async def set(self, provider: str, observable: NormalizedObservable, result: ProviderResult) -> None:
        """Caches result with appropriate TTL in Redis and memory fallback."""
        key = self.build_key(provider, observable)
        ttl = self.calculate_ttl(result)

        # Always update in-memory fallback
        await self._fallback.set(key, result, ttl)

        try:
            r = self._get_redis()
            payload = result.model_dump(mode="json")
            await r.set(key, json.dumps(payload), ex=ttl)
            if self._is_redis_degraded:
                logger.info("redis_cache_recovered_on_set", key=key)
                self._is_redis_degraded = False
        except (RedisConnectionError, RedisTimeoutError, OSError) as exc:
            if not self._is_redis_degraded:
                logger.warning("redis_cache_degraded_write_to_memory_only", error=str(exc))
                self._is_redis_degraded = True
        except Exception as exc:
            logger.error("redis_cache_set_error", error=str(exc))

    async def invalidate(
        self,
        provider: str | None = None,
        observable: NormalizedObservable | None = None,
        key_pattern: str | None = None,
    ) -> int:
        """
        Invalidates cached results matching criteria.
        Returns total number of invalidated entries across Redis and fallback.
        """
        if observable and provider:
            target_pattern = self.build_key(provider, observable)
        elif provider:
            target_pattern = f"ti:cache:{provider.lower()}:*"
        elif key_pattern:
            target_pattern = key_pattern
        else:
            target_pattern = "ti:cache:*"

        deleted_fallback = await self._fallback.invalidate(target_pattern)
        deleted_redis = 0

        try:
            r = self._get_redis()
            keys: list[str] = []
            async for k in r.scan_iter(match=target_pattern):
                keys.append(k)
            if keys:
                deleted_redis = await r.delete(*keys)
        except Exception as exc:
            logger.warning("redis_cache_invalidate_error", error=str(exc))

        return max(deleted_redis, deleted_fallback)

    async def check_health(self) -> dict[str, Any]:
        """Probes Redis connection status and fallback memory size."""
        redis_ok = False
        latency_ms = None

        try:
            r = self._get_redis()
            t0 = time.perf_counter()
            await r.ping()
            latency_ms = round((time.perf_counter() - t0) * 1000.0, 2)
            redis_ok = True
        except Exception:
            redis_ok = False

        return {
            "status": "healthy" if redis_ok else "degraded",
            "redis_connected": redis_ok,
            "latency_ms": latency_ms,
            "memory_fallback_entries": self._fallback.size(),
            "ttl_positive_seconds": self._ttl_positive,
            "ttl_negative_seconds": self._ttl_negative,
            "ttl_error_seconds": self._ttl_error,
        }

    async def close(self) -> None:
        """Closes Redis connection pool."""
        if self._owns_redis and self._redis:
            await self._redis.aclose()
