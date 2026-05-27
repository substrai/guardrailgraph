"""Tests for check result caching with content-hash deduplication."""

import threading
import time
from unittest.mock import patch

import pytest

from guardrailgraph.cache.result_cache import (
    CacheConfig,
    CacheEntry,
    CacheMetrics,
    ResultCache,
)


class TestCacheConfig:
    """Tests for CacheConfig validation."""

    def test_default_config(self):
        config = CacheConfig()
        assert config.max_size == 1024
        assert config.ttl_seconds == 300.0
        assert config.enabled is True
        assert config.hash_algorithm == "sha256"

    def test_custom_config(self):
        config = CacheConfig(max_size=100, ttl_seconds=60.0, hash_algorithm="md5")
        assert config.max_size == 100
        assert config.ttl_seconds == 60.0

    def test_invalid_max_size(self):
        with pytest.raises(ValueError, match="max_size must be at least 1"):
            CacheConfig(max_size=0)

    def test_invalid_ttl(self):
        with pytest.raises(ValueError, match="ttl_seconds must be positive"):
            CacheConfig(ttl_seconds=-1)

    def test_invalid_hash_algorithm(self):
        with pytest.raises(ValueError, match="Unsupported hash algorithm"):
            CacheConfig(hash_algorithm="not_a_real_algo")


class TestCacheEntry:
    """Tests for CacheEntry."""

    def test_not_expired(self):
        entry = CacheEntry(
            key="test",
            value="result",
            created_at=time.time(),
            expires_at=time.time() + 300,
        )
        assert not entry.is_expired

    def test_expired(self):
        entry = CacheEntry(
            key="test",
            value="result",
            created_at=time.time() - 600,
            expires_at=time.time() - 1,
        )
        assert entry.is_expired

    def test_age_seconds(self):
        entry = CacheEntry(
            key="test",
            value="result",
            created_at=time.time() - 10,
            expires_at=time.time() + 290,
        )
        assert 9.5 <= entry.age_seconds <= 11.0


class TestCacheMetrics:
    """Tests for CacheMetrics."""

    def test_hit_rate_zero_requests(self):
        metrics = CacheMetrics()
        assert metrics.hit_rate == 0.0
        assert metrics.miss_rate == 0.0

    def test_hit_rate_calculation(self):
        metrics = CacheMetrics(hits=75, misses=25, total_requests=100)
        assert metrics.hit_rate == 0.75
        assert metrics.miss_rate == 0.25

    def test_to_dict(self):
        metrics = CacheMetrics(hits=10, misses=5, evictions=2, total_requests=15)
        d = metrics.to_dict()
        assert d["hits"] == 10
        assert d["misses"] == 5
        assert d["evictions"] == 2
        assert d["hit_rate"] == pytest.approx(0.6667, abs=0.001)

    def test_reset(self):
        metrics = CacheMetrics(hits=10, misses=5, total_requests=15)
        metrics.reset()
        assert metrics.hits == 0
        assert metrics.misses == 0
        assert metrics.total_requests == 0


class TestResultCache:
    """Tests for ResultCache."""

    def test_basic_put_and_get(self):
        """Test basic cache put and get operations."""
        cache = ResultCache()
        cache.put("toxicity", "Hello world", {"detected": False, "score": 0.1})

        result = cache.get("toxicity", "Hello world")
        assert result is not None
        assert result["detected"] is False
        assert result["score"] == 0.1

    def test_cache_miss(self):
        """Test cache miss returns None."""
        cache = ResultCache()
        result = cache.get("toxicity", "unknown content")
        assert result is None

    def test_content_hash_deduplication(self):
        """Test that identical content produces cache hits."""
        cache = ResultCache()
        content = "This is a test message for deduplication"

        cache.put("pii-check", content, {"detected": True})

        # Same content should hit cache
        result = cache.get("pii-check", content)
        assert result is not None
        assert result["detected"] is True

    def test_different_checks_same_content(self):
        """Test that different check names create separate entries."""
        cache = ResultCache()
        content = "Hello world"

        cache.put("toxicity", content, {"score": 0.1})
        cache.put("pii", content, {"score": 0.9})

        assert cache.get("toxicity", content)["score"] == 0.1
        assert cache.get("pii", content)["score"] == 0.9

    def test_ttl_expiration(self):
        """Test that entries expire after TTL."""
        config = CacheConfig(ttl_seconds=0.1)  # 100ms TTL
        cache = ResultCache(config)

        cache.put("check", "content", {"result": True})
        assert cache.get("check", "content") is not None

        time.sleep(0.15)  # Wait for expiration
        assert cache.get("check", "content") is None

    def test_lru_eviction(self):
        """Test LRU eviction when cache is full."""
        config = CacheConfig(max_size=3)
        cache = ResultCache(config)

        cache.put("check", "content1", "result1")
        cache.put("check", "content2", "result2")
        cache.put("check", "content3", "result3")

        # Access content1 to make it recently used
        cache.get("check", "content1")

        # Add content4, should evict content2 (least recently used)
        cache.put("check", "content4", "result4")

        assert cache.get("check", "content1") is not None  # Still there (recently accessed)
        assert cache.get("check", "content2") is None  # Evicted
        assert cache.get("check", "content3") is not None
        assert cache.get("check", "content4") is not None

    def test_metrics_tracking(self):
        """Test that hit/miss metrics are tracked correctly."""
        cache = ResultCache()

        cache.put("check", "content", "result")
        cache.get("check", "content")  # Hit
        cache.get("check", "content")  # Hit
        cache.get("check", "missing")  # Miss

        assert cache.metrics.hits == 2
        assert cache.metrics.misses == 1
        assert cache.metrics.total_requests == 3
        assert cache.metrics.hit_rate == pytest.approx(0.6667, abs=0.001)

    def test_invalidate_specific(self):
        """Test invalidating a specific cache entry."""
        cache = ResultCache()
        cache.put("check", "content", "result")

        assert cache.invalidate("check", "content") is True
        assert cache.get("check", "content") is None
        assert cache.invalidate("check", "content") is False

    def test_invalidate_check(self):
        """Test invalidating all entries for a check."""
        cache = ResultCache()
        cache.put("toxicity", "content1", "r1")
        cache.put("toxicity", "content2", "r2")
        cache.put("pii", "content1", "r3")

        removed = cache.invalidate_check("toxicity")
        assert removed == 2
        assert cache.get("toxicity", "content1") is None
        assert cache.get("pii", "content1") is not None

    def test_clear(self):
        """Test clearing the entire cache."""
        cache = ResultCache()
        cache.put("check1", "c1", "r1")
        cache.put("check2", "c2", "r2")

        cache.clear()
        assert cache.size == 0

    def test_cleanup_expired(self):
        """Test cleanup of expired entries."""
        config = CacheConfig(ttl_seconds=0.1)
        cache = ResultCache(config)

        cache.put("check", "content1", "r1")
        cache.put("check", "content2", "r2")

        time.sleep(0.15)
        removed = cache.cleanup_expired()
        assert removed == 2
        assert cache.size == 0

    def test_disabled_cache(self):
        """Test that disabled cache always returns None."""
        config = CacheConfig(enabled=False)
        cache = ResultCache(config)

        cache.put("check", "content", "result")
        assert cache.get("check", "content") is None
        assert cache.size == 0

    def test_thread_safety(self):
        """Test concurrent access from multiple threads."""
        cache = ResultCache(CacheConfig(max_size=100))
        errors = []

        def writer(thread_id):
            try:
                for i in range(50):
                    cache.put("check", f"content-{thread_id}-{i}", f"result-{thread_id}-{i}")
            except Exception as e:
                errors.append(e)

        def reader(thread_id):
            try:
                for i in range(50):
                    cache.get("check", f"content-{thread_id}-{i}")
            except Exception as e:
                errors.append(e)

        threads = []
        for t in range(4):
            threads.append(threading.Thread(target=writer, args=(t,)))
            threads.append(threading.Thread(target=reader, args=(t,)))

        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert len(errors) == 0

    def test_contains_operator(self):
        """Test the 'in' operator for cache membership."""
        cache = ResultCache()
        cache.put("check", "content", "result")

        assert ("check", "content") in cache
        assert ("check", "missing") not in cache

    def test_update_existing_entry(self):
        """Test updating an existing cache entry."""
        cache = ResultCache()
        cache.put("check", "content", "old_result")
        cache.put("check", "content", "new_result")

        assert cache.get("check", "content") == "new_result"
        assert cache.size == 1

    def test_eviction_metrics(self):
        """Test that eviction metrics are tracked."""
        config = CacheConfig(max_size=2)
        cache = ResultCache(config)

        cache.put("check", "c1", "r1")
        cache.put("check", "c2", "r2")
        cache.put("check", "c3", "r3")  # Triggers eviction

        assert cache.metrics.evictions == 1
