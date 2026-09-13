"""
Sliding window state storage abstractions and implementations.

Provides:
  - WindowStateStore (ABC)
  - InMemoryWindowStateStore (Thread/async-safe local dictionary)
  - RedisWindowStateStore (Distributed sorted sets with degraded mode fallback)
"""

from __future__ import annotations

import abc
import asyncio
import json
from datetime import datetime, timezone
from typing import Any
from uuid import UUID

import structlog
from redis import asyncio as aioredis
from redis.exceptions import ConnectionError as RedisConnectionError, TimeoutError as RedisTimeoutError

from .models import WindowItem

logger = structlog.get_logger(__name__)


class WindowStateStore(abc.ABC):
    """Abstract interface for storing and retrieving sliding window events."""

    @abc.abstractmethod
    async def add_event(self, rule_id: UUID, entity_value: str, item: WindowItem) -> None:
        """Add an event to the sliding window for a given rule and entity."""
        pass

    @abc.abstractmethod
    async def get_events(
        self, rule_id: UUID, entity_value: str, start_time: datetime, end_time: datetime
    ) -> list[WindowItem]:
        """Retrieve all events within the temporal window [start_time, end_time], sorted by event_timestamp ASC."""
        pass

    @abc.abstractmethod
    async def prune_events(self, rule_id: UUID, entity_value: str, older_than: datetime) -> int:
        """Prune events older than the given timestamp. Returns count of pruned events."""
        pass

    @abc.abstractmethod
    async def clear(self) -> None:
        """Clear all stored state."""
        pass


class InMemoryWindowStateStore(WindowStateStore):
    """Hermetic, in-memory sliding window state store for unit testing and local execution."""

    def __init__(self) -> None:
        self._store: dict[str, list[WindowItem]] = {}
        self._lock = asyncio.Lock()

    def _make_key(self, rule_id: UUID, entity_value: str) -> str:
        return f"{rule_id}:{entity_value}"

    async def add_event(self, rule_id: UUID, entity_value: str, item: WindowItem) -> None:
        key = self._make_key(rule_id, entity_value)
        async with self._lock:
            if key not in self._store:
                self._store[key] = []
            self._store[key].append(item)
            # Maintain sorted order by event_timestamp
            self._store[key].sort(key=lambda x: x.event_timestamp)

    async def get_events(
        self, rule_id: UUID, entity_value: str, start_time: datetime, end_time: datetime
    ) -> list[WindowItem]:
        key = self._make_key(rule_id, entity_value)
        async with self._lock:
            items = self._store.get(key, [])
            # Filter strictly by [start_time, end_time]
            return [
                it for it in items
                if start_time <= it.event_timestamp <= end_time
            ]

    async def prune_events(self, rule_id: UUID, entity_value: str, older_than: datetime) -> int:
        key = self._make_key(rule_id, entity_value)
        async with self._lock:
            if key not in self._store:
                return 0
            original_len = len(self._store[key])
            self._store[key] = [it for it in self._store[key] if it.event_timestamp >= older_than]
            pruned_count = original_len - len(self._store[key])
            if not self._store[key]:
                del self._store[key]
            return pruned_count

    async def clear(self) -> None:
        async with self._lock:
            self._store.clear()


class RedisWindowStateStore(WindowStateStore):
    """
    Distributed sliding window state store using Redis sorted sets (ZSET).
    
    Scores are Unix epoch timestamps of the event_timestamp.
    Includes automated fallback to an internal in-memory store if Redis becomes unreachable.
    """

    def __init__(
        self,
        redis_url: str = "redis://127.0.0.1:6379/0",
        ttl_seconds: int = 7200,
        redis_client: aioredis.Redis | None = None,
    ) -> None:
        self._redis_url = redis_url
        self._ttl_seconds = ttl_seconds
        self._redis = redis_client
        self._fallback_store = InMemoryWindowStateStore()
        self.is_degraded: bool = False
        self._last_warning_time: float = 0.0

    async def _get_redis(self) -> aioredis.Redis:
        if self._redis is None:
            self._redis = aioredis.from_url(
                self._redis_url,
                encoding="utf-8",
                decode_responses=True,
                socket_timeout=2.0,
                socket_connect_timeout=2.0,
            )
        return self._redis

    def _make_key(self, rule_id: UUID, entity_value: str) -> str:
        return f"soc:window:{rule_id}:{entity_value}"

    def _handle_redis_error(self, err: Exception) -> None:
        if not self.is_degraded:
            self.is_degraded = True
            logger.warning(
                "redis_state_store_unreachable_falling_back_to_in_memory",
                error=str(err),
                degraded=True,
                warning="Lost cross-worker sliding window correlation guarantee while degraded.",
            )

    async def check_health(self) -> bool:
        """Probes Redis connectivity. Restores normal distributed mode upon recovery."""
        try:
            client = await self._get_redis()
            await client.ping()
            if self.is_degraded:
                self.is_degraded = False
                logger.info(
                    "redis_state_store_restored",
                    degraded=False,
                    action="Resuming distributed Redis sliding windows.",
                )
            return True
        except (RedisConnectionError, RedisTimeoutError, OSError) as err:
            self._handle_redis_error(err)
            return False

    async def add_event(self, rule_id: UUID, entity_value: str, item: WindowItem) -> None:
        if self.is_degraded:
            await self._fallback_store.add_event(rule_id, entity_value, item)
            return

        try:
            client = await self._get_redis()
            key = self._make_key(rule_id, entity_value)
            score = item.event_timestamp.timestamp()
            value = item.model_dump_json()

            async with client.pipeline(transaction=True) as pipe:
                pipe.zadd(key, {value: score})
                pipe.expire(key, self._ttl_seconds)
                await pipe.execute()
        except (RedisConnectionError, RedisTimeoutError, OSError) as err:
            self._handle_redis_error(err)
            await self._fallback_store.add_event(rule_id, entity_value, item)

    async def get_events(
        self, rule_id: UUID, entity_value: str, start_time: datetime, end_time: datetime
    ) -> list[WindowItem]:
        if self.is_degraded:
            return await self._fallback_store.get_events(rule_id, entity_value, start_time, end_time)

        try:
            client = await self._get_redis()
            key = self._make_key(rule_id, entity_value)
            min_score = start_time.timestamp()
            max_score = end_time.timestamp()

            raw_members = await client.zrangebyscore(key, min=min_score, max=max_score)
            items: list[WindowItem] = []
            for member in raw_members:
                try:
                    data = json.loads(member)
                    items.append(WindowItem.model_validate(data))
                except Exception as ex:
                    logger.error("corrupted_window_item_in_redis", error=str(ex))
            # Redis returns sorted by score ASC (which is event_timestamp)
            return items
        except (RedisConnectionError, RedisTimeoutError, OSError) as err:
            self._handle_redis_error(err)
            return await self._fallback_store.get_events(rule_id, entity_value, start_time, end_time)

    async def prune_events(self, rule_id: UUID, entity_value: str, older_than: datetime) -> int:
        if self.is_degraded:
            return await self._fallback_store.prune_events(rule_id, entity_value, older_than)

        try:
            client = await self._get_redis()
            key = self._make_key(rule_id, entity_value)
            max_score = older_than.timestamp() - 0.000001
            pruned = await client.zremrangebyscore(key, min="-inf", max=max_score)
            return int(pruned)
        except (RedisConnectionError, RedisTimeoutError, OSError) as err:
            self._handle_redis_error(err)
            return await self._fallback_store.prune_events(rule_id, entity_value, older_than)

    async def clear(self) -> None:
        await self._fallback_store.clear()
        try:
            client = await self._get_redis()
            # Scan and delete keys matching soc:window:*
            cursor = 0
            while True:
                cursor, keys = await client.scan(cursor=cursor, match="soc:window:*", count=100)
                if keys:
                    await client.delete(*keys)
                if cursor == 0:
                    break
        except (RedisConnectionError, RedisTimeoutError, OSError) as err:
            self._handle_redis_error(err)

    async def close(self) -> None:
        if self._redis is not None:
            await self._redis.aclose()
            self._redis = None
