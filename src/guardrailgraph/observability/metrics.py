"""Metrics collection for guardrail pipeline monitoring."""

from __future__ import annotations

import time
from collections import defaultdict
from typing import Any, Dict, List, Optional

from guardrailgraph.core.result import PipelineResult


class MetricsCollector:
    """Collects and aggregates pipeline execution metrics.

    Tracks:
    - Block rate (percentage of requests blocked)
    - Latency percentiles (P50, P95, P99)
    - Per-check detection rates
    - False positive estimates

    Args:
        window_seconds: Time window for metric aggregation.
    """

    def __init__(self, window_seconds: int = 3600):
        self.window_seconds = window_seconds
        self._results: List[Dict[str, Any]] = []
        self._check_stats: Dict[str, Dict[str, int]] = defaultdict(
            lambda: {"total": 0, "detected": 0, "blocked": 0}
        )

    def record(self, result: PipelineResult) -> None:
        """Record a pipeline execution result."""
        self._results.append({
            "timestamp": time.time(),
            "allowed": result.allowed,
            "action": result.action.value,
            "latency_ms": result.total_latency_ms,
            "check_count": len(result.check_results),
        })

        for check_result in result.check_results:
            stats = self._check_stats[check_result.name]
            stats["total"] += 1
            if check_result.detected:
                stats["detected"] += 1
            if check_result.blocked:
                stats["blocked"] += 1

    @property
    def total_requests(self) -> int:
        """Total number of requests processed."""
        return len(self._results)

    @property
    def block_rate(self) -> float:
        """Percentage of requests blocked."""
        if not self._results:
            return 0.0
        blocked = sum(1 for r in self._results if not r["allowed"])
        return blocked / len(self._results)

    @property
    def avg_latency_ms(self) -> float:
        """Average pipeline latency in milliseconds."""
        if not self._results:
            return 0.0
        return sum(r["latency_ms"] for r in self._results) / len(self._results)

    def latency_percentile(self, percentile: float) -> float:
        """Get latency at a given percentile (e.g., 0.95 for P95)."""
        if not self._results:
            return 0.0
        latencies = sorted(r["latency_ms"] for r in self._results)
        index = int(len(latencies) * percentile)
        return latencies[min(index, len(latencies) - 1)]

    def check_detection_rate(self, check_name: str) -> float:
        """Get detection rate for a specific check."""
        stats = self._check_stats.get(check_name)
        if not stats or stats["total"] == 0:
            return 0.0
        return stats["detected"] / stats["total"]

    def summary(self) -> Dict[str, Any]:
        """Get a summary of all metrics."""
        return {
            "total_requests": self.total_requests,
            "block_rate": self.block_rate,
            "avg_latency_ms": self.avg_latency_ms,
            "p50_latency_ms": self.latency_percentile(0.5),
            "p95_latency_ms": self.latency_percentile(0.95),
            "p99_latency_ms": self.latency_percentile(0.99),
            "check_stats": dict(self._check_stats),
        }
