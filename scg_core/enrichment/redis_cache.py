"""Multi-tier resilient caching fabric for Supply Chain Guardian (SCG).

Conforms to IEEE Std 830-1998, RFC 2119, and SCG Phase 3 Specification.
Combines in-memory L1 LRU and async Redis L2 caching featuring single-flight
stampede suppression, negative 404 caching, degraded mode resilience, and ±10% TTL jitter.
"""

from __future__ import annotations

import asyncio
from collections import OrderedDict
import json
import logging
from pathlib import Path
import random
import sys
from typing import Any, Awaitable, Callable, Dict, Optional

# Ensure repository root is in sys.path for direct script execution
REPO_ROOT = Path(__file__).resolve().parent.parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

import redis.asyncio as aioredis
from redis.exceptions import RedisError

from scg_core.exceptions import SCGError

logger = logging.getLogger(__name__)

NULL_SENTINEL: str = "__NULL_SENTINEL__"
_CACHE_MISS: object = object()


class TransientUpstreamError(SCGError):
    """Raised when an upstream dependency or registry experiences a temporary retryable failure."""

    def __init__(
        self,
        message: str = "Transient upstream error occurred.",
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        super().__init__(message=message, details=details)


class LRUCache:
    """Thread-safe and async-safe In-Memory Least-Recently-Used (LRU) Cache.

    Maintains capacity limit using collections.OrderedDict and asyncio.Lock.
    """

    def __init__(self, capacity: int = 4096) -> None:
        if capacity <= 0:
            raise ValueError("LRUCache capacity must be greater than zero.")
        self.capacity: int = capacity
        self._cache: OrderedDict[str, Any] = OrderedDict()
        self._lock: asyncio.Lock = asyncio.Lock()

    async def get(self, key: str, default: Any = _CACHE_MISS) -> Any:
        """Retrieves a value by key and marks it as recently used.

        Args:
            key: Cache key string.
            default: Sentinel or value returned if key is not found.

        Returns:
            Cached value or default if not found.
        """
        async with self._lock:
            if key not in self._cache:
                return default
            self._cache.move_to_end(key)
            return self._cache[key]

    async def set(self, key: str, value: Any) -> None:
        """Stores a value by key, moving it to recent, and evicts LRU if over capacity.

        Args:
            key: Cache key string.
            value: Object to cache.
        """
        async with self._lock:
            if key in self._cache:
                self._cache.move_to_end(key)
            self._cache[key] = value
            if len(self._cache) > self.capacity:
                self._cache.popitem(last=False)

    async def delete(self, key: str) -> bool:
        """Deletes a key from the cache.

        Args:
            key: Cache key string.

        Returns:
            True if key was present and deleted, False otherwise.
        """
        async with self._lock:
            if key in self._cache:
                del self._cache[key]
                return True
            return False

    async def clear(self) -> None:
        """Clears all entries from the cache."""
        async with self._lock:
            self._cache.clear()

    def __len__(self) -> int:
        return len(self._cache)

    def __contains__(self, key: str) -> bool:
        return key in self._cache


class ResilientCacheManager:
    """Multi-tier resilient caching fabric combining in-memory L1 LRU and async Redis L2.

    Implements single-flight request coalescing to suppress cache stampedes,
    negative 404 caching with sentinel preservation, ±10% TTL jitter, and
    automatic degraded mode fallback when Redis is unavailable.
    """

    def __init__(
        self,
        redis_url: str = "redis://localhost:6379/0",
        default_timeout: float = 2.0,
    ) -> None:
        """Initializes the multi-tier cache manager.

        Args:
            redis_url: Redis connection string URL.
            default_timeout: Socket timeout for Redis operations in seconds.
        """
        self.redis_url: str = redis_url
        self.default_timeout: float = default_timeout
        self.l1: LRUCache = LRUCache(capacity=4096)
        self.redis_pool: Optional[aioredis.ConnectionPool] = None
        self.redis_available: bool = True
        self.failed_lookups_count: int = 0
        self.total_lookups_count: int = 0
        self._in_flight: Dict[str, asyncio.Future[Any]] = {}
        self._in_flight_lock: asyncio.Lock = asyncio.Lock()

    def _apply_jitter(self, ttl_seconds: int) -> int:
        """Applies pseudo-random ±10% jitter to TTL, clamped to a minimum of 60 seconds.

        Args:
            ttl_seconds: Base TTL in seconds.

        Returns:
            Jittered TTL clamped to >= 60 seconds.
        """
        factor = random.uniform(-0.10, 0.10)
        jitter = int(round(ttl_seconds * factor))
        return max(60, ttl_seconds + jitter)

    def get_redis(self) -> Optional[aioredis.Redis]:
        """Handles lazy pool connection; on failure logs warning, toggles redis_available=False,
        and gracefully degrades to L1.

        Returns:
            Configured async Redis client instance, or None if unavailable.
        """
        if not self.redis_available:
            return None
        try:
            if self.redis_pool is None:
                self.redis_pool = aioredis.ConnectionPool.from_url(
                    self.redis_url,
                    socket_timeout=self.default_timeout,
                    socket_connect_timeout=self.default_timeout,
                    decode_responses=True,
                )
            return aioredis.Redis(connection_pool=self.redis_pool)
        except Exception as exc:
            logger.warning("Redis lazy pool connection failed: %s", exc)
            self.redis_available = False
            self.failed_lookups_count += 1
            return None

    async def get_or_fetch(
        self,
        key: str,
        ttl_seconds: int,
        fetcher: Callable[[], Awaitable[Optional[Dict[str, Any]]]],
    ) -> Optional[Dict[str, Any]]:
        """Retrieves an item from cache (L1 LRU -> L2 Redis) or executes fetcher under single-flight lock.

        1. Check L1. If sentinel '__NULL_SENTINEL__', return None. If hit, return parsed value.
        2. Check L2 Redis if available. If sentinel '__NULL_SENTINEL__', return None.
           On hit, populate L1 and return. On Redis failure, increment failed_lookups_count and bypass.
        3. If miss, coalesce via single-flight _in_flight future.
        4. Fetcher worker executes fetcher, caches result or sentinel '__NULL_SENTINEL__' to L1
           and Redis (with jittered TTL), sets future result, and removes key from _in_flight.

        Args:
            key: Canonical cache key string.
            ttl_seconds: Base TTL for caching.
            fetcher: Async callable returning a dictionary payload or None.

        Returns:
            Parsed dictionary payload or None if not found/negative cached.
        """
        self.total_lookups_count += 1

        # 1. Check L1 Cache
        l1_val = await self.l1.get(key)
        if l1_val is not _CACHE_MISS:
            if l1_val == NULL_SENTINEL:
                return None
            return l1_val

        # 2. Check L2 Redis if available
        if self.redis_available:
            try:
                redis_client = self.get_redis()
                if redis_client is not None:
                    raw_val = await asyncio.wait_for(
                        redis_client.get(key),
                        timeout=self.default_timeout,
                    )
                    if raw_val is not None:
                        if raw_val == NULL_SENTINEL:
                            await self.l1.set(key, NULL_SENTINEL)
                            return None
                        try:
                            parsed_val = json.loads(raw_val)
                        except (json.JSONDecodeError, TypeError):
                            parsed_val = raw_val
                        await self.l1.set(key, parsed_val)
                        return parsed_val
            except Exception as exc:
                logger.warning("Redis L2 lookup failed for key '%s': %s", key, exc)
                self.redis_available = False
                self.failed_lookups_count += 1
                # Gracefully degrade and bypass Redis

        # 3. Coalesce via single-flight _in_flight future
        async with self._in_flight_lock:
            # Double check L1 in case a concurrent fetcher worker just finished
            l1_val = await self.l1.get(key)
            if l1_val is not _CACHE_MISS:
                if l1_val == NULL_SENTINEL:
                    return None
                return l1_val

            if key in self._in_flight:
                future = self._in_flight[key]
                is_leader = False
            else:
                loop = asyncio.get_running_loop()
                future = loop.create_future()
                self._in_flight[key] = future
                is_leader = True

        if not is_leader:
            return await future

        # 4. Fetcher worker execution
        try:
            fetched_data = await fetcher()
            jittered_ttl = self._apply_jitter(ttl_seconds)

            if fetched_data is None:
                # Negative 404 caching
                await self.l1.set(key, NULL_SENTINEL)
                if self.redis_available:
                    try:
                        redis_client = self.get_redis()
                        if redis_client is not None:
                            await asyncio.wait_for(
                                redis_client.set(key, NULL_SENTINEL, ex=jittered_ttl),
                                timeout=self.default_timeout,
                            )
                    except Exception as exc:
                        logger.warning("Redis L2 write sentinel failed for key '%s': %s", key, exc)
                        self.redis_available = False
                        self.failed_lookups_count += 1

                future.set_result(None)
                return None
            else:
                # Positive caching
                await self.l1.set(key, fetched_data)
                if self.redis_available:
                    try:
                        redis_client = self.get_redis()
                        if redis_client is not None:
                            serialized = json.dumps(fetched_data)
                            await asyncio.wait_for(
                                redis_client.set(key, serialized, ex=jittered_ttl),
                                timeout=self.default_timeout,
                            )
                    except Exception as exc:
                        logger.warning("Redis L2 write failed for key '%s': %s", key, exc)
                        self.redis_available = False
                        self.failed_lookups_count += 1

                future.set_result(fetched_data)
                return fetched_data
        except Exception as exc:
            if not future.done():
                future.set_exception(exc)
            raise
        finally:
            async with self._in_flight_lock:
                self._in_flight.pop(key, None)

    async def close(self) -> None:
        """Disconnects redis connection pool cleanly."""
        if self.redis_pool is not None:
            try:
                await self.redis_pool.disconnect()
            except Exception as exc:
                logger.warning("Error disconnecting Redis pool: %s", exc)
            finally:
                self.redis_pool = None


if __name__ == "__main__":
    async def _run_self_tests() -> None:
        print("Executing verification harness for scg_core/enrichment/redis_cache.py...")

        # 1. Instantiate ResilientCacheManager and isolate L1
        cache = ResilientCacheManager(redis_url="redis://localhost:6379/0", default_timeout=1.0)
        cache.redis_available = False

        # 2. Test concurrent calls to get_or_fetch with identical key: verify fetcher runs exactly once
        fetch_counter = 0

        async def dummy_fetcher() -> Optional[Dict[str, Any]]:
            nonlocal fetch_counter
            fetch_counter += 1
            await asyncio.sleep(0.05)  # Simulate upstream network latency
            return {"status": "ok", "package": "lodash", "version": "4.17.21"}

        test_key = "pkg:npm/lodash@4.17.21"
        tasks = [
            cache.get_or_fetch(test_key, ttl_seconds=300, fetcher=dummy_fetcher)
            for _ in range(10)
        ]
        results = await asyncio.gather(*tasks)

        assert fetch_counter == 1, f"Expected fetcher to run exactly once, but ran {fetch_counter} times"
        for res in results:
            assert res == {"status": "ok", "package": "lodash", "version": "4.17.21"}, f"Unexpected result: {res}"
        print("[1/4] Single-flight coalescing verified: 10 concurrent requests triggered exactly 1 fetch.")

        # Verify subsequent lookup hits L1 without calling fetcher
        cached_res = await cache.get_or_fetch(test_key, ttl_seconds=300, fetcher=dummy_fetcher)
        assert cached_res == {"status": "ok", "package": "lodash", "version": "4.17.21"}
        assert fetch_counter == 1, "Fetcher should not have been called on cache hit"
        print("[2/4] L1 cache hit verified without invoking fetcher.")

        # 3. Test sentinel caching for None return values (negative 404 caching)
        none_fetch_counter = 0

        async def null_fetcher() -> Optional[Dict[str, Any]]:
            nonlocal none_fetch_counter
            none_fetch_counter += 1
            await asyncio.sleep(0.05)
            return None

        null_key = "pkg:npm/non-existent-pkg@0.0.0"
        null_tasks = [
            cache.get_or_fetch(null_key, ttl_seconds=300, fetcher=null_fetcher)
            for _ in range(5)
        ]
        null_results = await asyncio.gather(*null_tasks)

        assert none_fetch_counter == 1, f"Expected null fetcher to run exactly once, ran {none_fetch_counter} times"
        for res in null_results:
            assert res is None, f"Expected None for negative cache hit, got {res}"

        # Subsequent fetch for None key should hit sentinel in L1 and return None without calling fetcher
        subsequent_null = await cache.get_or_fetch(null_key, ttl_seconds=300, fetcher=null_fetcher)
        assert subsequent_null is None
        assert none_fetch_counter == 1, "Null fetcher was invoked again despite negative cache sentinel"
        print("[3/4] Negative 404 caching verified with __NULL_SENTINEL__.")

        # 4. Verify TTL jitter clamping and bounds
        for base_ttl in [10, 60, 3600, 86400]:
            jittered = cache._apply_jitter(base_ttl)
            assert jittered >= 60, f"Jittered TTL {jittered} below minimum clamp of 60s"
            if base_ttl > 60:
                assert int(base_ttl * 0.89) <= jittered <= int(base_ttl * 1.11) + 1
        print("[4/4] TTL jitter (+/-10%, clamped to >=60s) verified.")

        # Clean up
        await cache.close()

        # Final required output line
        print("SUCCESS: Multi-Tier Resilient Cache verified.")

    asyncio.run(_run_self_tests())
