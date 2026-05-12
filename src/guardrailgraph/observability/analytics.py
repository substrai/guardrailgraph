"""Guardrail analytics — real-time metrics, block rates, false positive tracking.

Provides comprehensive analytics for guardrail pipeline performance:
- Block/pass rates over time
- Per-check detection rates
- Latency percentiles
- False positive estimation
- Trend analysis
"""

from __future__ import annotations

import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Any, Deque, Dict, List, Optional, Tuple

from guardrailgraph.core.actions import Action
from guardrailgraph.core.result import CheckResult, PipelineResult


@dataclass
class TimeWindow:
    """A time-windowed metric bucket."""

    start_time: float
    end_time: float
    total: int = 0
    blocked: int = 0
    passed: int = 0
    flagged: int = 0
    redacted: int = 0
    total_latency_ms: float = 0.0


@dataclass
class CheckAnalytics:
    """Analytics for a single check."""

    name: str
    total_executions: int = 0
    detections: int = 0
    false_positives: int = 0  # Manually marked
    avg_confidence: float = 0.0
    avg_latency_ms: float = 0.0
    _confidence_sum: float = 0.0
    _latency_sum: float = 0.0

    @property
    def detection_rate(self) -> float:
        return self.detections / max(self.total_executions, 1)

    @property
    def false_positive_rate(self) -> float:
        return self.false_positives / max(self.detections, 1)

    def record(self, result: CheckResult) -> None:
        """Record a check execution."""
        self.total_executions += 1
        self._latency_sum += result.latency_ms
        self.avg_latency_ms = self._latency_sum / self.total_executions

        if result.detected:
            self.detections += 1
            self._confidence_sum += result.confidence
            self.avg_confidence = self._confidence_sum / self.detections


class GuardrailAnalytics:
    """Comprehensive analytics engine for guardrail pipelines.

    Tracks metrics over configurable time windows and provides
    real-time insights into pipeline performance.

    Args:
        window_size_seconds: Size of each time window bucket.
        max_windows: Maximum number of windows to retain.
        alert_block_rate: Alert if block rate exceeds this threshold.

    Example:
        analytics = GuardrailAnalytics()
        analytics.record(pipeline_result)

        summary = analytics.summary()
        print(f"Block rate: {summary['block_rate']:.2%}")
    """

    def __init__(
        self,
        window_size_seconds: int = 300,  # 5-minute windows
        max_windows: int = 288,  # 24 hours of 5-min windows
        alert_block_rate: float = 0.1,
    ):
        self.window_size_seconds = window_size_seconds
        self.max_windows = max_windows
        self.alert_block_rate = alert_block_rate

        self._windows: Deque[TimeWindow] = deque(maxlen=max_windows)
        self._check_analytics: Dict[str, CheckAnalytics] = {}
        self._total_requests: int = 0
        self._total_blocked: int = 0
        self._total_passed: int = 0
        self._latencies: Deque[float] = deque(maxlen=10000)
        self._alerts: List[Dict[str, Any]] = []

    def record(self, result: PipelineResult) -> None:
        """Record a pipeline execution result.

        Args:
            result: The pipeline result to record.
        """
        now = time.time()
        self._total_requests += 1
        self._latencies.append(result.total_latency_ms)

        # Update totals
        if result.allowed:
            self._total_passed += 1
        else:
            self._total_blocked += 1

        # Update time window
        window = self._get_or_create_window(now)
        window.total += 1
        window.total_latency_ms += result.total_latency_ms

        if not result.allowed:
            window.blocked += 1
        else:
            window.passed += 1

        if result.flagged_checks:
            window.flagged += 1
        if result.redacted_checks:
            window.redacted += 1

        # Update per-check analytics
        for check_result in result.check_results:
            if check_result.name not in self._check_analytics:
                self._check_analytics[check_result.name] = CheckAnalytics(
                    name=check_result.name
                )
            self._check_analytics[check_result.name].record(check_result)

        # Check for alerts
        self._check_alerts()

    def mark_false_positive(self, check_name: str, count: int = 1) -> None:
        """Mark a detection as a false positive.

        Args:
            check_name: The check that produced the false positive.
            count: Number of false positives to record.
        """
        if check_name in self._check_analytics:
            self._check_analytics[check_name].false_positives += count

    def summary(self, last_n_minutes: Optional[int] = None) -> Dict[str, Any]:
        """Get analytics summary.

        Args:
            last_n_minutes: Only include data from the last N minutes.

        Returns:
            Dict with comprehensive analytics.
        """
        if last_n_minutes:
            cutoff = time.time() - (last_n_minutes * 60)
            windows = [w for w in self._windows if w.end_time >= cutoff]
            total = sum(w.total for w in windows)
            blocked = sum(w.blocked for w in windows)
            passed = sum(w.passed for w in windows)
        else:
            total = self._total_requests
            blocked = self._total_blocked
            passed = self._total_passed

        latencies = sorted(self._latencies)

        return {
            "total_requests": total,
            "blocked": blocked,
            "passed": passed,
            "block_rate": blocked / max(total, 1),
            "pass_rate": passed / max(total, 1),
            "avg_latency_ms": sum(latencies) / max(len(latencies), 1),
            "p50_latency_ms": self._percentile(latencies, 0.5),
            "p95_latency_ms": self._percentile(latencies, 0.95),
            "p99_latency_ms": self._percentile(latencies, 0.99),
            "checks": {
                name: {
                    "detection_rate": ca.detection_rate,
                    "false_positive_rate": ca.false_positive_rate,
                    "avg_confidence": ca.avg_confidence,
                    "avg_latency_ms": ca.avg_latency_ms,
                    "total_executions": ca.total_executions,
                }
                for name, ca in self._check_analytics.items()
            },
            "alerts": self._alerts[-10:],  # Last 10 alerts
        }

    def check_summary(self, check_name: str) -> Optional[Dict[str, Any]]:
        """Get analytics for a specific check."""
        ca = self._check_analytics.get(check_name)
        if not ca:
            return None
        return {
            "name": ca.name,
            "total_executions": ca.total_executions,
            "detections": ca.detections,
            "detection_rate": ca.detection_rate,
            "false_positives": ca.false_positives,
            "false_positive_rate": ca.false_positive_rate,
            "avg_confidence": ca.avg_confidence,
            "avg_latency_ms": ca.avg_latency_ms,
        }

    def trend(self, metric: str = "block_rate", windows: int = 12) -> List[Tuple[float, float]]:
        """Get trend data for a metric over recent time windows.

        Args:
            metric: Metric to track ("block_rate", "latency", "total").
            windows: Number of recent windows to include.

        Returns:
            List of (timestamp, value) tuples.
        """
        recent = list(self._windows)[-windows:]
        result = []

        for window in recent:
            if metric == "block_rate":
                value = window.blocked / max(window.total, 1)
            elif metric == "latency":
                value = window.total_latency_ms / max(window.total, 1)
            elif metric == "total":
                value = float(window.total)
            else:
                value = 0.0
            result.append((window.start_time, value))

        return result

    def _get_or_create_window(self, timestamp: float) -> TimeWindow:
        """Get or create the time window for the given timestamp."""
        window_start = (int(timestamp) // self.window_size_seconds) * self.window_size_seconds
        window_end = window_start + self.window_size_seconds

        if self._windows and self._windows[-1].start_time == window_start:
            return self._windows[-1]

        window = TimeWindow(start_time=window_start, end_time=window_end)
        self._windows.append(window)
        return window

    def _check_alerts(self) -> None:
        """Check if any alert thresholds are exceeded."""
        if len(self._windows) < 2:
            return

        current_window = self._windows[-1]
        if current_window.total < 5:
            return

        block_rate = current_window.blocked / current_window.total
        if block_rate > self.alert_block_rate:
            self._alerts.append({
                "type": "high_block_rate",
                "timestamp": time.time(),
                "block_rate": block_rate,
                "threshold": self.alert_block_rate,
                "window_total": current_window.total,
            })

    @staticmethod
    def _percentile(sorted_values: List[float], p: float) -> float:
        """Calculate percentile from sorted values."""
        if not sorted_values:
            return 0.0
        index = int(len(sorted_values) * p)
        return sorted_values[min(index, len(sorted_values) - 1)]
