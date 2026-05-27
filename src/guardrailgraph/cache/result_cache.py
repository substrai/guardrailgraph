"""Check result caching with content-hash deduplication for GuardrailGraph.

Provides an LRU cache keyed by (check_name + content_hash) with configurable
TTL, thread-safety, and cache hit/miss metrics for guardrail check results.
"""

from __future__ import annotations

import hashlib
import logging
import threading
import time
from collections import OrderedDict
from dataclasses import dataclass, field
from typing import Any, Dict, Optional

logger = logging.getLogger("guardrailgraph.cache")


@dataclass
class CacheConfig:
    """Configuration for the result cache.

    Attributes:
        max_size: Maximum number of entries in the cache (LRU eviction).
        ttl_seconds: Time-to-live for cache entries in seconds.
        enabled: Whether caching is enabled.
        hash_algorithm: Hash algorithm for content deduplication.
    """
    max_size: int = 1024
    ttl_seconds: float = 300.0  # 5 minutes default
    enabled: bool = True
    hash_algorithm: str = "sha256"

    def __post_init__(self):
        if self.max_size < 1:
            raise ValueError("max_size must be at least 1")
        if self.ttl_seconds <= 0:
            raise ValueError("ttl_seconds must be positive")
        if self.hash_algorithm not in hashlib.algorithms_available:
            raise ValueError(f"Unsupported hash algorithm: {self.hash_algorithm}")


@dataclass
class CacheEntry:
    """A single cache entry with metadata.

    Attributes:
        key: The cache key (check_name + content_hash).
        value: The cached check result.
        created_at: Timestamp when the entry was created.
        expires_at: Timestamp when the entry expires.
        access_count: Number of times this entry has been accessed.
    """
    key: str
    value: Any
    created_at: float
    expires_at: float
    access_count: int = 0

    @property
    def is_expired(self) -> bool:
        """Check if this entry has expired."""
        return time.time() > self.expires_at

    @property
    def age_seconds(self) -> float:
        """Get the age of this entry in seconds."""
        return time.time() - self.created_at


@dataclass
class CacheMetrics:
    """Metrics for cache performance monitoring.

    Attributes:
        hits: Number of cache hits.
        misses: Number of cache misses.
        evictions: Number of LRU evictions.
        expirations: Number of TTL expirations.
        total_requests: Total number of cache lookups.
    """
    hits: int = 0
    misses: int = 0
    evictions: int = 0
    expirations: int = 0
    total_requests: int = 0

    @property
    def hit_rate(self) -> float:
        """Calculate the cache hit rate."""
        if self.total_requests == 0:
            return 0.0
        return self.hits / self.total_requests

    @property
    def miss_rate(self) -> float:
        """Calculate the cache miss rate."""
        if self.total_requests == 0:
            return 0.0
        return self.misses / self.total_requests

    def to_dict(self) -> Dict[str, Any]:
        """Convert metrics to a dictionary."""
        return {
            "hits": self.hits,
            "misses": self.misses,
            "evictions": self.evictions,
            "expirations": self.expirations,
            "total_requests": self.total_requests,
            "hit_rate": round(self.hit_rate, 4),
            "miss_rate": round(self.miss_rate, 4),
        }

    def reset(self) -> None:
        """Reset all metrics to zero."""
        self.hits = 0
        self.misses = 0
        self.evictions = 0
        self.expirations = 0
        self.total_requests = 0


class ResultCache:
    """Thread-safe LRU cache for guardrail check results with content-hash deduplication.

    Caches check results keyed by (check_name, content_hash) to avoid
    re-running expensive checks on identical content. Supports configurable
    TTL, LRU eviction, and provides hit/miss metrics.

    Usage:
        cache = ResultCache(CacheConfig(max_size=512, ttl_seconds=60))

        # Check cache before running expensive check
        result = cache.get("toxicity", "Hello world")
        if result is None:
            result = run_toxicity_check("Hello world")
            cache.put("toxicity", "Hello world", result)

        # Monitor performance
        print(cache.metrics.hit_rate)
    """

    def __init__(self, config: Optional[CacheConfig] = None):
        self._config = config or CacheConfig()
        self._cache: OrderedDict[str, CacheEntry] = OrderedDict()
        self._lock = threading.RLock()
        self._metrics = CacheMetrics()

    @property
    def config(self) -> CacheConfig:
        """Get the cache configuration."""
        return self._config

    @property
    def metrics(self) -> CacheMetrics:
        """Get cache metrics."""
        return self._metrics

    @property
    def size(self) -> int:
        """Get the current number of entries in the cache."""
        with self._lock:
            return len(self._cache)

    def get(self, check_name: str, content: str) -> Optional[Any]:
        """Look up a cached result by check name and content.

        Args:
            check_name: The name of the guardrail check.
            content: The content that was checked.

        Returns:
            The cached result if found and not expired, None otherwise.
        """
        if not self._config.enabled:
            return None

        key = self._make_key(check_name, content)

        with self._lock:
            self._metrics.total_requests += 1

            if key not in self._cache:
                self._metrics.misses += 1
                return None

            entry = self._cache[key]

            # Check TTL expiration
            if entry.is_expired:
                del self._cache[key]
                self._metrics.expirations += 1
                self._metrics.misses += 1
                return None

            # Move to end (most recently used)
            self._cache.move_to_end(key)
            entry.access_count += 1
            self._metrics.hits += 1
            return entry.value

    def put(self, check_name: str, content: str, result: Any) -> None:
        """Store a check result in the cache.

        Args:
            check_name: The name of the guardrail check.
            content: The content that was checked.
            result: The check result to cache.
        """
        if not self._config.enabled:
            return

        key = self._make_key(check_name, content)
        now = time.time()

        with self._lock:
            # If key exists, update it
            if key in self._cache:
                self._cache.move_to_end(key)
                self._cache[key] = CacheEntry(
                    key=key,
                    value=result,
                    created_at=now,
                    expires_at=now + self._config.ttl_seconds,
                )
                return

            # Evict if at capacity
            while len(self._cache) >= self._config.max_size:
                evicted_key, _ = self._cache.popitem(last=False)
                self._metrics.evictions += 1
                logger.debug(f"Evicted cache entry: {evicted_key[:16]}...")

            # Insert new entry
            self._cache[key] = CacheEntry(
                key=key,
                value=result,
                created_at=now,
                expires_at=now + self._config.ttl_seconds,
            )

    def invalidate(self, check_name: str, content: str) -> bool:
        """Invalidate a specific cache entry.

        Args:
            check_name: The name of the guardrail check.
            content: The content that was checked.

        Returns:
            True if an entry was removed, False if not found.
        """
        key = self._make_key(check_name, content)

        with self._lock:
            if key in self._cache:
                del self._cache[key]
                return True
            return False

    def invalidate_check(self, check_name: str) -> int:
        """Invalidate all cached results for a specific check.

        Args:
            check_name: The name of the guardrail check.

        Returns:
            Number of entries removed.
        """
        prefix = f"{check_name}:"
        removed = 0

        with self._lock:
            keys_to_remove = [k for k in self._cache if k.startswith(prefix)]
            for key in keys_to_remove:
                del self._cache[key]
                removed += 1

        return removed

    def clear(self) -> None:
        """Clear all entries from the cache."""
        with self._lock:
            self._cache.clear()

    def cleanup_expired(self) -> int:
        """Remove all expired entries from the cache.

        Returns:
            Number of expired entries removed.
        """
        removed = 0

        with self._lock:
            expired_keys = [
                key for key, entry in self._cache.items()
                if entry.is_expired
            ]
            for key in expired_keys:
                del self._cache[key]
                self._metrics.expirations += 1
                removed += 1

        return removed

    def get_entry(self, check_name: str, content: str) -> Optional[CacheEntry]:
        """Get the full cache entry (including metadata) for inspection.

        Args:
            check_name: The name of the guardrail check.
            content: The content that was checked.

        Returns:
            The CacheEntry if found, None otherwise.
        """
        key = self._make_key(check_name, content)

        with self._lock:
            return self._cache.get(key)

    def _make_key(self, check_name: str, content: str) -> str:
        """Generate a cache key from check name and content hash.

        Uses content hashing for deduplication - identical content
        will always produce the same cache key regardless of when
        it was submitted.
        """
        content_hash = hashlib.new(
            self._config.hash_algorithm,
            content.encode("utf-8"),
        ).hexdigest()
        return f"{check_name}:{content_hash}"

    def _content_hash(self, content: str) -> str:
        """Compute the content hash for deduplication."""
        return hashlib.new(
            self._config.hash_algorithm,
            content.encode("utf-8"),
        ).hexdigest()

    def __len__(self) -> int:
        """Return the number of entries in the cache."""
        return self.size

    def __contains__(self, item: tuple) -> bool:
        """Check if a (check_name, content) tuple is in the cache."""
        if isinstance(item, tuple) and len(item) == 2:
            check_name, content = item
            key = self._make_key(check_name, content)
            with self._lock:
                if key in self._cache:
                    return not self._cache[key].is_expired
        return False

    def __repr__(self) -> str:
        return (
            f"ResultCache(size={self.size}, max_size={self._config.max_size}, "
            f"ttl={self._config.ttl_seconds}s, hit_rate={self._metrics.hit_rate:.2%})"
        )
