"""Unit tests for ResilientCacheManager and LRUCache in Phase 3 Track B."""

import asyncio
from typing import Any, Dict, Optional
import pytest

from scg_core.enrichment.redis_cache import (
    LRUCache,
    NULL_SENTINEL,
    ResilientCacheManager,
    TransientUpstreamError,
)
from scg_core.exceptions import SCGError


def test_transient_upstream_error():
    """Validates TransientUpstreamError inheritance and metadata retention."""
    err = TransientUpstreamError("API timeout", details={"upstream": "OSV", "retry_after": 5})
    assert isinstance(err, Exception)
    assert isinstance(err, SCGError)
    assert err.details["upstream"] == "OSV"
    assert "API timeout" in str(err)


@pytest.mark.asyncio
async def test_lru_cache_basic_and_eviction():
    """Validates LRUCache capacity management and LRU eviction order."""
    lru = LRUCache(capacity=3)

    await lru.set("k1", "v1")
    await lru.set("k2", "v2")
    await lru.set("k3", "v3")

    # Access k1 to make it most recently used
    assert await lru.get("k1") == "v1"

    # Insert k4, which should evict k2 (the least recently used)
    await lru.set("k4", "v4")

    assert await lru.get("k1") == "v1"
    assert await lru.get("k3") == "v3"
    assert await lru.get("k4") == "v4"
    assert "k2" not in lru

    # Test delete and clear
    assert await lru.delete("k3") is True
    assert await lru.delete("k3") is False
    assert len(lru) == 2

    await lru.clear()
    assert len(lru) == 0


@pytest.mark.asyncio
async def test_single_flight_stampede_suppression():
    """Validates that concurrent requests for the same key trigger exactly one upstream fetch."""
    cache = ResilientCacheManager()
    cache.redis_available = False

    fetch_counter = 0

    async def fetcher() -> Optional[Dict[str, Any]]:
        nonlocal fetch_counter
        fetch_counter += 1
        await asyncio.sleep(0.05)
        return {"id": "GHSA-1234", "severity": "HIGH"}

    key = "pkg:npm/vulnerable-pkg@1.0.0"

    tasks = [cache.get_or_fetch(key, ttl_seconds=300, fetcher=fetcher) for _ in range(8)]
    results = await asyncio.gather(*tasks)

    assert fetch_counter == 1, "Fetcher should be called exactly once across 8 concurrent requests"
    for r in results:
        assert r == {"id": "GHSA-1234", "severity": "HIGH"}

    # Subsequent lookup should hit L1
    cached = await cache.get_or_fetch(key, ttl_seconds=300, fetcher=fetcher)
    assert cached == {"id": "GHSA-1234", "severity": "HIGH"}
    assert fetch_counter == 1

    await cache.close()


@pytest.mark.asyncio
async def test_negative_404_caching():
    """Validates negative caching of None values using NULL_SENTINEL."""
    cache = ResilientCacheManager()
    cache.redis_available = False

    null_fetch_counter = 0

    async def null_fetcher() -> Optional[Dict[str, Any]]:
        nonlocal null_fetch_counter
        null_fetch_counter += 1
        await asyncio.sleep(0.05)
        return None

    key = "pkg:npm/missing-pkg@9.9.9"

    tasks = [cache.get_or_fetch(key, ttl_seconds=300, fetcher=null_fetcher) for _ in range(5)]
    results = await asyncio.gather(*tasks)

    assert null_fetch_counter == 1
    for r in results:
        assert r is None

    # L1 must have cached NULL_SENTINEL
    l1_entry = await cache.l1.get(key)
    assert l1_entry == NULL_SENTINEL

    # Subsequent fetcher call returns None directly without invoking null_fetcher
    subsequent = await cache.get_or_fetch(key, ttl_seconds=300, fetcher=null_fetcher)
    assert subsequent is None
    assert null_fetch_counter == 1

    await cache.close()


@pytest.mark.asyncio
async def test_single_flight_error_propagation():
    """Validates that fetcher exceptions propagate to all concurrent callers and remove in-flight key."""
    cache = ResilientCacheManager()
    cache.redis_available = False

    async def failing_fetcher() -> Optional[Dict[str, Any]]:
        await asyncio.sleep(0.05)
        raise TransientUpstreamError("Simulated upstream 503")

    key = "pkg:npm/failing-pkg@1.0.0"

    tasks = [cache.get_or_fetch(key, ttl_seconds=300, fetcher=failing_fetcher) for _ in range(4)]
    results = await asyncio.gather(*tasks, return_exceptions=True)

    for res in results:
        assert isinstance(res, TransientUpstreamError)
        assert "Simulated upstream 503" in str(res)

    # In-flight map should be cleared after exception
    assert key not in cache._in_flight

    await cache.close()


def test_jitter_calculation():
    """Validates that _apply_jitter keeps values within ±10% and clamped to >= 60 seconds."""
    cache = ResilientCacheManager()

    # Base TTL below minimum clamp
    assert cache._apply_jitter(30) >= 60
    assert cache._apply_jitter(59) >= 60

    # Base TTL of 3600 (±360 seconds)
    for _ in range(50):
        jittered = cache._apply_jitter(3600)
        assert 3240 <= jittered <= 3960


@pytest.mark.asyncio
async def test_degraded_mode_redis_failure():
    """Validates that cache manager degrades gracefully to L1 when Redis connection fails."""
    # Use invalid host/port to simulate unavailable Redis
    cache = ResilientCacheManager(redis_url="redis://127.0.0.1:1/0", default_timeout=0.1)

    fetch_counter = 0

    async def fetcher() -> Optional[Dict[str, Any]]:
        nonlocal fetch_counter
        fetch_counter += 1
        return {"data": "fallback"}

    # First lookup should detect Redis failure, degrade to L1, and return fetcher result
    result = await cache.get_or_fetch("degraded-test-key", ttl_seconds=120, fetcher=fetcher)
    assert result == {"data": "fallback"}
    assert fetch_counter == 1
    assert cache.redis_available is False
    assert cache.failed_lookups_count > 0

    # Subsequent lookup should hit L1 without attempting Redis or calling fetcher
    subsequent = await cache.get_or_fetch("degraded-test-key", ttl_seconds=120, fetcher=fetcher)
    assert subsequent == {"data": "fallback"}
    assert fetch_counter == 1

    await cache.close()
