"""Pipeline execution metrics: latency, pass/block rates, and export support.

Provides per-check and pipeline-level metrics collection including latency
percentiles (p50/p95/p99), pass/block/error rates, with CloudWatch and
OTLP export capabilities.
"""

from __future__ import annotations

import math
import time
from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional, Protocol


class CheckResult(str, Enum):
    """Result of a guardrail check execution."""
    PASS = "pass"
    BLOCK = "block"
    ERROR = "error"


@dataclass
class LatencyStats:
    """Latency statistics with percentile calculations."""
    values: list[float] = field(default_factory=list)

    def record(self, duration_ms: float) -> None:
        """Record a latency measurement in milliseconds."""
        self.values.append(duration_ms)

    @property
    def count(self) -> int:
        return len(self.values)

    @property
    def p50(self) -> float:
        """50th percentile (median) latency."""
        return self._percentile(50)

    @property
    def p95(self) -> float:
        """95th percentile latency."""
        return self._percentile(95)

    @property
    def p99(self) -> float:
        """99th percentile latency."""
        return self._percentile(99)

    @property
    def mean(self) -> float:
        """Mean latency."""
        if not self.values:
            return 0.0
        return sum(self.values) / len(self.values)

    def _percentile(self, p: float) -> float:
        """Calculate the p-th percentile of recorded values."""
        if not self.values:
            return 0.0
        sorted_values = sorted(self.values)
        index = (p / 100.0) * (len(sorted_values) - 1)
        lower = int(math.floor(index))
        upper = int(math.ceil(index))
        if lower == upper:
            return sorted_values[lower]
        fraction = index - lower
        return sorted_values[lower] * (1 - fraction) + sorted_values[upper] * fraction

    def reset(self) -> None:
        """Clear all recorded values."""
        self.values.clear()


@dataclass
class CheckMetrics:
    """Metrics for a single guardrail check."""
    name: str
    latency: LatencyStats = field(default_factory=LatencyStats)
    pass_count: int = 0
    block_count: int = 0
    error_count: int = 0

    @property
    def total_count(self) -> int:
        return self.pass_count + self.block_count + self.error_count

    @property
    def pass_rate(self) -> float:
        """Pass rate as a fraction (0.0 to 1.0)."""
        if self.total_count == 0:
            return 0.0
        return self.pass_count / self.total_count

    @property
    def block_rate(self) -> float:
        """Block rate as a fraction (0.0 to 1.0)."""
        if self.total_count == 0:
            return 0.0
        return self.block_count / self.total_count

    @property
    def error_rate(self) -> float:
        """Error rate as a fraction (0.0 to 1.0)."""
        if self.total_count == 0:
            return 0.0
        return self.error_count / self.total_count

    def record(self, result: CheckResult, duration_ms: float) -> None:
        """Record a check execution result and latency."""
        self.latency.record(duration_ms)
        if result == CheckResult.PASS:
            self.pass_count += 1
        elif result == CheckResult.BLOCK:
            self.block_count += 1
        elif result == CheckResult.ERROR:
            self.error_count += 1

    def reset(self) -> None:
        """Reset all metrics."""
        self.latency.reset()
        self.pass_count = 0
        self.block_count = 0
        self.error_count = 0


@dataclass
class PipelineMetrics:
    """Aggregate metrics for an entire guardrail pipeline."""
    pipeline_name: str
    latency: LatencyStats = field(default_factory=LatencyStats)
    total_executions: int = 0
    total_pass: int = 0
    total_block: int = 0
    total_error: int = 0

    @property
    def pass_rate(self) -> float:
        if self.total_executions == 0:
            return 0.0
        return self.total_pass / self.total_executions

    @property
    def block_rate(self) -> float:
        if self.total_executions == 0:
            return 0.0
        return self.total_block / self.total_executions

    @property
    def error_rate(self) -> float:
        if self.total_executions == 0:
            return 0.0
        return self.total_error / self.total_executions

    def record_execution(self, result: CheckResult, duration_ms: float) -> None:
        """Record a pipeline execution."""
        self.latency.record(duration_ms)
        self.total_executions += 1
        if result == CheckResult.PASS:
            self.total_pass += 1
        elif result == CheckResult.BLOCK:
            self.total_block += 1
        elif result == CheckResult.ERROR:
            self.total_error += 1

    def reset(self) -> None:
        """Reset all pipeline metrics."""
        self.latency.reset()
        self.total_executions = 0
        self.total_pass = 0
        self.total_block = 0
        self.total_error = 0


class MetricsExporter(Protocol):
    """Protocol for metrics exporters."""

    def export_check_metrics(self, metrics: CheckMetrics) -> None:
        """Export metrics for a single check."""
        ...

    def export_pipeline_metrics(self, metrics: PipelineMetrics) -> None:
        """Export pipeline-level metrics."""
        ...


class CloudWatchExporter:
    """Export metrics to AWS CloudWatch.

    Args:
        namespace: CloudWatch namespace for the metrics.
        region: AWS region for CloudWatch.
        dimensions: Additional dimensions to attach to metrics.
    """

    def __init__(
        self,
        namespace: str = "GuardrailGraph",
        region: str = "us-east-1",
        dimensions: Optional[dict[str, str]] = None,
    ):
        self.namespace = namespace
        self.region = region
        self.dimensions = dimensions or {}
        self._buffer: list[dict[str, Any]] = []

    def export_check_metrics(self, metrics: CheckMetrics) -> None:
        """Export check metrics to CloudWatch format."""
        dims = {**self.dimensions, "CheckName": metrics.name}
        self._buffer.extend([
            {
                "MetricName": "CheckLatencyP50",
                "Value": metrics.latency.p50,
                "Unit": "Milliseconds",
                "Dimensions": dims,
            },
            {
                "MetricName": "CheckLatencyP95",
                "Value": metrics.latency.p95,
                "Unit": "Milliseconds",
                "Dimensions": dims,
            },
            {
                "MetricName": "CheckLatencyP99",
                "Value": metrics.latency.p99,
                "Unit": "Milliseconds",
                "Dimensions": dims,
            },
            {
                "MetricName": "CheckPassRate",
                "Value": metrics.pass_rate,
                "Unit": "None",
                "Dimensions": dims,
            },
            {
                "MetricName": "CheckBlockRate",
                "Value": metrics.block_rate,
                "Unit": "None",
                "Dimensions": dims,
            },
        ])

    def export_pipeline_metrics(self, metrics: PipelineMetrics) -> None:
        """Export pipeline metrics to CloudWatch format."""
        dims = {**self.dimensions, "PipelineName": metrics.pipeline_name}
        self._buffer.extend([
            {
                "MetricName": "PipelineLatencyP50",
                "Value": metrics.latency.p50,
                "Unit": "Milliseconds",
                "Dimensions": dims,
            },
            {
                "MetricName": "PipelineLatencyP95",
                "Value": metrics.latency.p95,
                "Unit": "Milliseconds",
                "Dimensions": dims,
            },
            {
                "MetricName": "PipelineTotalExecutions",
                "Value": metrics.total_executions,
                "Unit": "Count",
                "Dimensions": dims,
            },
        ])

    def flush(self) -> list[dict[str, Any]]:
        """Flush buffered metrics and return them."""
        data = self._buffer.copy()
        self._buffer.clear()
        return data


class OTLPExporter:
    """Export metrics via OpenTelemetry Protocol (OTLP).

    Args:
        endpoint: OTLP collector endpoint URL.
        service_name: Service name for resource attribution.
        headers: Optional headers for authentication.
    """

    def __init__(
        self,
        endpoint: str = "http://localhost:4317",
        service_name: str = "guardrailgraph",
        headers: Optional[dict[str, str]] = None,
    ):
        self.endpoint = endpoint
        self.service_name = service_name
        self.headers = headers or {}
        self._buffer: list[dict[str, Any]] = []

    def export_check_metrics(self, metrics: CheckMetrics) -> None:
        """Export check metrics in OTLP format."""
        self._buffer.append({
            "resource": {"service.name": self.service_name},
            "scope": "guardrailgraph.checks",
            "metrics": [
                {"name": f"check.{metrics.name}.latency.p50", "value": metrics.latency.p50, "unit": "ms"},
                {"name": f"check.{metrics.name}.latency.p95", "value": metrics.latency.p95, "unit": "ms"},
                {"name": f"check.{metrics.name}.latency.p99", "value": metrics.latency.p99, "unit": "ms"},
                {"name": f"check.{metrics.name}.pass_rate", "value": metrics.pass_rate, "unit": "ratio"},
                {"name": f"check.{metrics.name}.block_rate", "value": metrics.block_rate, "unit": "ratio"},
                {"name": f"check.{metrics.name}.error_rate", "value": metrics.error_rate, "unit": "ratio"},
            ],
        })

    def export_pipeline_metrics(self, metrics: PipelineMetrics) -> None:
        """Export pipeline metrics in OTLP format."""
        self._buffer.append({
            "resource": {"service.name": self.service_name},
            "scope": "guardrailgraph.pipeline",
            "metrics": [
                {"name": f"pipeline.{metrics.pipeline_name}.latency.p50", "value": metrics.latency.p50, "unit": "ms"},
                {"name": f"pipeline.{metrics.pipeline_name}.latency.p95", "value": metrics.latency.p95, "unit": "ms"},
                {"name": f"pipeline.{metrics.pipeline_name}.total_executions", "value": metrics.total_executions, "unit": "count"},
                {"name": f"pipeline.{metrics.pipeline_name}.pass_rate", "value": metrics.pass_rate, "unit": "ratio"},
                {"name": f"pipeline.{metrics.pipeline_name}.block_rate", "value": metrics.block_rate, "unit": "ratio"},
            ],
        })

    def flush(self) -> list[dict[str, Any]]:
        """Flush buffered metrics and return them."""
        data = self._buffer.copy()
        self._buffer.clear()
        return data


class MetricsCollector:
    """Central metrics collector for guardrail pipeline execution.

    Collects per-check and pipeline-level metrics and supports
    exporting to multiple backends (CloudWatch, OTLP).

    Args:
        pipeline_name: Name of the pipeline being monitored.
        exporters: List of metrics exporters to use.
    """

    def __init__(
        self,
        pipeline_name: str,
        exporters: Optional[list[MetricsExporter]] = None,
    ):
        self.pipeline_name = pipeline_name
        self.exporters = exporters or []
        self._check_metrics: dict[str, CheckMetrics] = {}
        self._pipeline_metrics = PipelineMetrics(pipeline_name=pipeline_name)

    def record_check(self, check_name: str, result: CheckResult, duration_ms: float) -> None:
        """Record a single check execution.

        Args:
            check_name: Name of the guardrail check.
            result: The check result (pass/block/error).
            duration_ms: Execution duration in milliseconds.
        """
        if check_name not in self._check_metrics:
            self._check_metrics[check_name] = CheckMetrics(name=check_name)
        self._check_metrics[check_name].record(result, duration_ms)

    def record_pipeline_execution(self, result: CheckResult, duration_ms: float) -> None:
        """Record a full pipeline execution.

        Args:
            result: The overall pipeline result.
            duration_ms: Total pipeline execution duration in milliseconds.
        """
        self._pipeline_metrics.record_execution(result, duration_ms)

    def get_check_metrics(self, check_name: str) -> Optional[CheckMetrics]:
        """Get metrics for a specific check."""
        return self._check_metrics.get(check_name)

    def get_pipeline_metrics(self) -> PipelineMetrics:
        """Get pipeline-level metrics."""
        return self._pipeline_metrics

    def get_all_check_metrics(self) -> dict[str, CheckMetrics]:
        """Get all check metrics."""
        return dict(self._check_metrics)

    def export(self) -> None:
        """Export all metrics to configured exporters."""
        for exporter in self.exporters:
            for check_metrics in self._check_metrics.values():
                exporter.export_check_metrics(check_metrics)
            exporter.export_pipeline_metrics(self._pipeline_metrics)

    def reset(self) -> None:
        """Reset all collected metrics."""
        for check_metrics in self._check_metrics.values():
            check_metrics.reset()
        self._pipeline_metrics.reset()

    def summary(self) -> dict[str, Any]:
        """Get a summary of all collected metrics.

        Returns:
            Dictionary with pipeline and per-check metric summaries.
        """
        return {
            "pipeline": {
                "name": self.pipeline_name,
                "total_executions": self._pipeline_metrics.total_executions,
                "pass_rate": self._pipeline_metrics.pass_rate,
                "block_rate": self._pipeline_metrics.block_rate,
                "error_rate": self._pipeline_metrics.error_rate,
                "latency_p50": self._pipeline_metrics.latency.p50,
                "latency_p95": self._pipeline_metrics.latency.p95,
                "latency_p99": self._pipeline_metrics.latency.p99,
            },
            "checks": {
                name: {
                    "total_count": m.total_count,
                    "pass_rate": m.pass_rate,
                    "block_rate": m.block_rate,
                    "error_rate": m.error_rate,
                    "latency_p50": m.latency.p50,
                    "latency_p95": m.latency.p95,
                    "latency_p99": m.latency.p99,
                }
                for name, m in self._check_metrics.items()
            },
        }
