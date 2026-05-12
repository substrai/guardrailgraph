"""Dashboard data provider — CloudWatch metrics and summary views.

Provides structured data for dashboards (CloudWatch, Grafana, custom).
"""

from __future__ import annotations

import json
import time
from typing import Any, Dict, List, Optional

from guardrailgraph.core.pipeline import Pipeline
from guardrailgraph.observability.analytics import GuardrailAnalytics


class DashboardProvider:
    """Provides dashboard-ready data from analytics.

    Formats metrics for CloudWatch, Grafana, or custom dashboards.

    Args:
        analytics: The analytics engine to pull data from.
        pipeline: The pipeline being monitored.
        namespace: CloudWatch namespace.

    Example:
        dashboard = DashboardProvider(analytics=my_analytics, pipeline=my_pipeline)
        widgets = dashboard.get_widgets()
    """

    def __init__(
        self,
        analytics: GuardrailAnalytics,
        pipeline: Optional[Pipeline] = None,
        namespace: str = "GuardrailGraph",
    ):
        self.analytics = analytics
        self.pipeline = pipeline
        self.namespace = namespace

    def get_summary(self) -> Dict[str, Any]:
        """Get dashboard summary data."""
        summary = self.analytics.summary()
        return {
            "overview": {
                "total_requests": summary["total_requests"],
                "block_rate": f"{summary['block_rate']:.1%}",
                "pass_rate": f"{summary['pass_rate']:.1%}",
                "avg_latency": f"{summary['avg_latency_ms']:.1f}ms",
                "p95_latency": f"{summary['p95_latency_ms']:.1f}ms",
            },
            "checks": summary.get("checks", {}),
            "alerts": summary.get("alerts", []),
            "timestamp": time.time(),
        }

    def get_cloudwatch_metrics(self) -> List[Dict[str, Any]]:
        """Format metrics for AWS CloudWatch PutMetricData.

        Returns:
            List of CloudWatch metric data points.
        """
        summary = self.analytics.summary()
        timestamp = time.time()

        metrics = [
            {
                "MetricName": "BlockRate",
                "Value": summary["block_rate"],
                "Unit": "None",
                "Timestamp": timestamp,
                "Dimensions": [{"Name": "Pipeline", "Value": self.pipeline.name if self.pipeline else "default"}],
            },
            {
                "MetricName": "TotalRequests",
                "Value": summary["total_requests"],
                "Unit": "Count",
                "Timestamp": timestamp,
                "Dimensions": [{"Name": "Pipeline", "Value": self.pipeline.name if self.pipeline else "default"}],
            },
            {
                "MetricName": "AvgLatency",
                "Value": summary["avg_latency_ms"],
                "Unit": "Milliseconds",
                "Timestamp": timestamp,
                "Dimensions": [{"Name": "Pipeline", "Value": self.pipeline.name if self.pipeline else "default"}],
            },
            {
                "MetricName": "P95Latency",
                "Value": summary["p95_latency_ms"],
                "Unit": "Milliseconds",
                "Timestamp": timestamp,
                "Dimensions": [{"Name": "Pipeline", "Value": self.pipeline.name if self.pipeline else "default"}],
            },
        ]

        # Per-check metrics
        for check_name, check_stats in summary.get("checks", {}).items():
            metrics.append({
                "MetricName": "DetectionRate",
                "Value": check_stats["detection_rate"],
                "Unit": "None",
                "Timestamp": timestamp,
                "Dimensions": [
                    {"Name": "Pipeline", "Value": self.pipeline.name if self.pipeline else "default"},
                    {"Name": "Check", "Value": check_name},
                ],
            })

        return metrics

    def get_cloudwatch_dashboard_body(self) -> str:
        """Generate CloudWatch Dashboard JSON body.

        Returns:
            JSON string for CloudWatch Dashboard source.
        """
        pipeline_name = self.pipeline.name if self.pipeline else "default"

        widgets = [
            {
                "type": "metric",
                "properties": {
                    "title": "Block Rate",
                    "metrics": [[self.namespace, "BlockRate", "Pipeline", pipeline_name]],
                    "period": 300,
                    "stat": "Average",
                },
                "width": 8,
                "height": 6,
            },
            {
                "type": "metric",
                "properties": {
                    "title": "Request Volume",
                    "metrics": [[self.namespace, "TotalRequests", "Pipeline", pipeline_name]],
                    "period": 300,
                    "stat": "Sum",
                },
                "width": 8,
                "height": 6,
            },
            {
                "type": "metric",
                "properties": {
                    "title": "Latency (P95)",
                    "metrics": [[self.namespace, "P95Latency", "Pipeline", pipeline_name]],
                    "period": 300,
                    "stat": "Maximum",
                },
                "width": 8,
                "height": 6,
            },
        ]

        return json.dumps({"widgets": widgets})
