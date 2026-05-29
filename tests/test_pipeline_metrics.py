"""Tests for pipeline execution metrics collection and export."""

import pytest

from guardrailgraph.metrics.pipeline_metrics import (
    CheckMetrics,
    CheckResult,
    CloudWatchExporter,
    LatencyStats,
    MetricsCollector,
    OTLPExporter,
    PipelineMetrics,
)


class TestLatencyStats:
    """Tests for latency percentile calculations."""

    def test_percentile_calculations(self):
        """Test p50/p95/p99 calculations with known data."""
        stats = LatencyStats()
        for i in range(1, 101):
            stats.record(float(i))

        assert stats.p50 == pytest.approx(50.5, abs=0.5)
        assert stats.p95 == pytest.approx(95.05, abs=0.5)
        assert stats.p99 == pytest.approx(99.01, abs=0.5)

    def test_empty_stats_return_zero(self):
        """Test that empty stats return 0.0 for all percentiles."""
        stats = LatencyStats()
        assert stats.p50 == 0.0
        assert stats.p95 == 0.0
        assert stats.p99 == 0.0
        assert stats.mean == 0.0

    def test_single_value(self):
        """Test stats with a single recorded value."""
        stats = LatencyStats()
        stats.record(42.0)
        assert stats.p50 == 42.0
        assert stats.p99 == 42.0
        assert stats.count == 1

    def test_reset_clears_values(self):
        """Test that reset clears all recorded values."""
        stats = LatencyStats()
        stats.record(10.0)
        stats.record(20.0)
        stats.reset()
        assert stats.count == 0
        assert stats.p50 == 0.0


class TestCheckMetrics:
    """Tests for per-check metrics."""

    def test_record_pass_block_error(self):
        """Test recording different check results."""
        metrics = CheckMetrics(name="toxicity")
        metrics.record(CheckResult.PASS, 10.0)
        metrics.record(CheckResult.PASS, 12.0)
        metrics.record(CheckResult.BLOCK, 15.0)
        metrics.record(CheckResult.ERROR, 100.0)

        assert metrics.pass_count == 2
        assert metrics.block_count == 1
        assert metrics.error_count == 1
        assert metrics.total_count == 4
        assert metrics.pass_rate == pytest.approx(0.5)
        assert metrics.block_rate == pytest.approx(0.25)
        assert metrics.error_rate == pytest.approx(0.25)

    def test_rates_with_no_executions(self):
        """Test that rates are 0.0 with no executions."""
        metrics = CheckMetrics(name="pii")
        assert metrics.pass_rate == 0.0
        assert metrics.block_rate == 0.0
        assert metrics.error_rate == 0.0


class TestMetricsCollector:
    """Tests for the central MetricsCollector."""

    def test_record_check_creates_metrics(self):
        """Test that recording a check creates metrics entry."""
        collector = MetricsCollector(pipeline_name="content-safety")
        collector.record_check("toxicity", CheckResult.PASS, 5.0)
        collector.record_check("toxicity", CheckResult.BLOCK, 8.0)

        check = collector.get_check_metrics("toxicity")
        assert check is not None
        assert check.total_count == 2

    def test_record_pipeline_execution(self):
        """Test pipeline-level execution recording."""
        collector = MetricsCollector(pipeline_name="moderation")
        collector.record_pipeline_execution(CheckResult.PASS, 50.0)
        collector.record_pipeline_execution(CheckResult.BLOCK, 45.0)

        pipeline = collector.get_pipeline_metrics()
        assert pipeline.total_executions == 2
        assert pipeline.pass_rate == pytest.approx(0.5)

    def test_summary_includes_all_metrics(self):
        """Test that summary returns complete metrics overview."""
        collector = MetricsCollector(pipeline_name="safety")
        collector.record_check("pii", CheckResult.PASS, 3.0)
        collector.record_pipeline_execution(CheckResult.PASS, 10.0)

        summary = collector.summary()
        assert "pipeline" in summary
        assert "checks" in summary
        assert summary["pipeline"]["name"] == "safety"
        assert "pii" in summary["checks"]

    def test_export_to_cloudwatch(self):
        """Test exporting metrics to CloudWatch exporter."""
        cw = CloudWatchExporter(namespace="TestNS")
        collector = MetricsCollector(pipeline_name="test", exporters=[cw])
        collector.record_check("check1", CheckResult.PASS, 10.0)
        collector.record_pipeline_execution(CheckResult.PASS, 20.0)
        collector.export()

        data = cw.flush()
        assert len(data) > 0
        metric_names = [d["MetricName"] for d in data]
        assert "CheckLatencyP50" in metric_names
        assert "PipelineLatencyP50" in metric_names

    def test_export_to_otlp(self):
        """Test exporting metrics to OTLP exporter."""
        otlp = OTLPExporter(endpoint="http://localhost:4317")
        collector = MetricsCollector(pipeline_name="test", exporters=[otlp])
        collector.record_check("bias", CheckResult.BLOCK, 7.0)
        collector.record_pipeline_execution(CheckResult.BLOCK, 15.0)
        collector.export()

        data = otlp.flush()
        assert len(data) == 2
        assert data[0]["scope"] == "guardrailgraph.checks"
        assert data[1]["scope"] == "guardrailgraph.pipeline"

    def test_reset_clears_all_metrics(self):
        """Test that reset clears all collected metrics."""
        collector = MetricsCollector(pipeline_name="test")
        collector.record_check("check1", CheckResult.PASS, 5.0)
        collector.record_pipeline_execution(CheckResult.PASS, 10.0)
        collector.reset()

        assert collector.get_pipeline_metrics().total_executions == 0
        check = collector.get_check_metrics("check1")
        assert check.total_count == 0
