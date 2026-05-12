"""Tests for Phase 4 — Observability & Deployment."""

import json
import pytest
from guardrailgraph import pipeline, check, Action, Pipeline
from guardrailgraph.checks import pii_check, toxicity_check, injection_check
from guardrailgraph.observability.alerts import AlertManager, AlertRule, AlertSeverity, AlertChannel
from guardrailgraph.observability.reports import ReportGenerator, ComplianceReport
from guardrailgraph.observability.dashboard import DashboardProvider
from guardrailgraph.observability.analytics import GuardrailAnalytics
from guardrailgraph.observability.audit import AuditLogger


class TestAlertSystem:
    """Test alert manager and rules."""

    def _make_pipeline(self):
        @check(name="blocker", action=Action.BLOCK)
        def block_bad(text: str) -> dict:
            return {"detected": "bad" in text, "confidence": 0.9}
        return pipeline(name="test", checks=[block_bad])

    def test_alert_on_block(self):
        """Alert fires when content is blocked."""
        alerts_received = []
        manager = AlertManager(
            channels=[AlertChannel.CALLBACK],
            on_alert=lambda a: alerts_received.append(a),
        )
        manager.add_block_rule(cooldown_seconds=0)

        p = self._make_pipeline()
        result = p.run("bad content")
        manager.evaluate(result)

        assert len(alerts_received) == 1
        assert alerts_received[0].severity == AlertSeverity.WARNING

    def test_no_alert_on_pass(self):
        """No alert when content passes."""
        alerts_received = []
        manager = AlertManager(
            channels=[AlertChannel.CALLBACK],
            on_alert=lambda a: alerts_received.append(a),
        )
        manager.add_block_rule()

        p = self._make_pipeline()
        result = p.run("good content")
        manager.evaluate(result)

        assert len(alerts_received) == 0

    def test_alert_cooldown(self):
        """Alert respects cooldown period."""
        alerts_received = []
        manager = AlertManager(
            channels=[AlertChannel.CALLBACK],
            on_alert=lambda a: alerts_received.append(a),
        )
        manager.add_block_rule(cooldown_seconds=9999)

        p = self._make_pipeline()
        # First block triggers alert
        manager.evaluate(p.run("bad 1"))
        # Second block within cooldown does NOT trigger
        manager.evaluate(p.run("bad 2"))

        assert len(alerts_received) == 1

    def test_custom_alert_rule(self):
        """Custom alert rules work."""
        alerts_received = []
        manager = AlertManager(
            channels=[AlertChannel.CALLBACK],
            on_alert=lambda a: alerts_received.append(a),
        )
        manager.add_rule(AlertRule(
            name="custom",
            condition=lambda r: r.total_latency_ms > 0,  # Always true
            severity=AlertSeverity.INFO,
            cooldown_seconds=0,
        ))

        p = self._make_pipeline()
        manager.evaluate(p.run("anything"))

        assert len(alerts_received) == 1
        assert alerts_received[0].severity == AlertSeverity.INFO

    def test_alert_slack_payload(self):
        """Alert generates valid Slack payload."""
        from guardrailgraph.observability.alerts import Alert
        alert = Alert(
            id="test-1",
            severity=AlertSeverity.CRITICAL,
            title="Test Alert",
            message="Something happened",
            pipeline_name="my-pipeline",
            check_name="toxicity",
        )
        payload = alert.to_slack_payload()
        assert "attachments" in payload
        assert payload["attachments"][0]["color"] == "#ff0000"

    def test_alert_stats(self):
        """Alert manager tracks statistics."""
        manager = AlertManager(channels=[AlertChannel.CONSOLE])
        manager.add_block_rule(cooldown_seconds=0)

        p = self._make_pipeline()
        for _ in range(3):
            manager.evaluate(p.run("bad"))

        stats = manager.stats()
        assert stats["total_alerts"] == 3


class TestComplianceReports:
    """Test compliance report generation."""

    def test_generate_report(self):
        """Generate a basic compliance report."""
        p = pipeline(
            name="test-pipeline",
            checks=[pii_check(), toxicity_check(), injection_check()],
        )
        generator = ReportGenerator(pipeline=p, framework="general")
        report = generator.generate()

        assert report.pipeline_name == "test-pipeline"
        assert report.framework == "general"
        assert len(report.checks_inventory) == 3

    def test_report_to_json(self):
        """Report exports to valid JSON."""
        p = pipeline(name="test", checks=[pii_check()])
        generator = ReportGenerator(pipeline=p, framework="HIPAA")
        report = generator.generate()

        json_str = report.to_json()
        parsed = json.loads(json_str)
        assert parsed["framework"] == "HIPAA"
        assert "checks_inventory" in parsed

    def test_report_to_text(self):
        """Report exports to formatted text."""
        p = pipeline(name="test", checks=[pii_check()])
        generator = ReportGenerator(pipeline=p, framework="HIPAA")
        report = generator.generate()

        text = report.to_text()
        assert "COMPLIANCE REPORT" in text
        assert "HIPAA" in text
        assert "pii-detection" in text

    def test_hipaa_compliance_assessment(self):
        """HIPAA compliance assessment detects missing checks."""
        # Pipeline without required HIPAA checks
        @check(name="custom", action=Action.BLOCK)
        def custom(text: str) -> dict:
            return {"detected": False, "confidence": 0.0}

        p = pipeline(name="test", checks=[custom])
        generator = ReportGenerator(pipeline=p, framework="HIPAA")
        report = generator.generate()

        assert report.compliance_status == "non_compliant"
        assert len(report.findings) > 0

    def test_report_with_analytics(self):
        """Report includes analytics data when available."""
        p = pipeline(name="test", checks=[pii_check()])
        analytics = GuardrailAnalytics()

        # Record some data
        for text in ["hello", "SSN: 123-45-6789", "world"]:
            analytics.record(p.run(text))

        generator = ReportGenerator(pipeline=p, analytics=analytics, framework="general")
        report = generator.generate()

        assert report.statistics["total_requests_processed"] == 3


class TestDashboard:
    """Test dashboard data provider."""

    def test_get_summary(self):
        """Dashboard provides summary data."""
        p = pipeline(name="test", checks=[pii_check()])
        analytics = GuardrailAnalytics()

        for text in ["hello", "SSN: 123-45-6789"]:
            analytics.record(p.run(text))

        dashboard = DashboardProvider(analytics=analytics, pipeline=p)
        summary = dashboard.get_summary()

        assert "overview" in summary
        assert "total_requests" in summary["overview"]

    def test_cloudwatch_metrics(self):
        """Dashboard generates CloudWatch metric data."""
        p = pipeline(name="test", checks=[pii_check()])
        analytics = GuardrailAnalytics()
        analytics.record(p.run("hello"))

        dashboard = DashboardProvider(analytics=analytics, pipeline=p)
        metrics = dashboard.get_cloudwatch_metrics()

        assert len(metrics) >= 4
        assert metrics[0]["MetricName"] == "BlockRate"

    def test_cloudwatch_dashboard_body(self):
        """Dashboard generates valid CloudWatch dashboard JSON."""
        analytics = GuardrailAnalytics()
        dashboard = DashboardProvider(analytics=analytics)
        body = dashboard.get_cloudwatch_dashboard_body()

        parsed = json.loads(body)
        assert "widgets" in parsed


class TestAuditLogger:
    """Test audit trail logging."""

    def test_log_result(self):
        """Audit logger records pipeline results."""
        import tempfile
        import os

        log_file = tempfile.mktemp(suffix=".jsonl")
        logger = AuditLogger(backend="local", log_file=log_file)

        p = pipeline(name="test", checks=[pii_check()])
        result = p.run("My SSN is 123-45-6789")

        record = logger.log(result, request_id="req-001", user_id="user-1")

        assert record["request_id"] == "req-001"
        assert record["pipeline_name"] == "test"
        assert logger.record_count == 1

        # Verify file was written
        assert os.path.exists(log_file)
        with open(log_file) as f:
            line = f.readline()
            parsed = json.loads(line)
            assert parsed["request_id"] == "req-001"

        os.unlink(log_file)

    def test_get_records(self):
        """Audit logger retrieves records."""
        logger = AuditLogger(backend="local", log_file="/dev/null")

        p = pipeline(name="test", checks=[pii_check()])
        logger.log(p.run("text 1"))
        logger.log(p.run("text 2"))
        logger.log(p.run("text 3"))

        records = logger.get_records()
        assert len(records) == 3

    def test_filter_by_pipeline(self):
        """Audit logger filters by pipeline name."""
        logger = AuditLogger(backend="local", log_file="/dev/null")

        p1 = pipeline(name="pipeline-a", checks=[pii_check()])
        p2 = pipeline(name="pipeline-b", checks=[pii_check()])

        logger.log(p1.run("text"))
        logger.log(p2.run("text"))
        logger.log(p1.run("text"))

        records = logger.get_records(pipeline_name="pipeline-a")
        assert len(records) == 2


class TestCLICommands:
    """Test CLI deploy, report, eject commands."""

    def test_deploy_dry_run(self):
        """Deploy command generates infrastructure in dry-run mode."""
        import tempfile
        import os
        from guardrailgraph.cli.commands import deploy

        # Create a temp config
        config_dir = tempfile.mkdtemp()
        config_path = os.path.join(config_dir, "guardrailgraph.yaml")
        with open(config_path, "w") as f:
            f.write("""
project:
  name: test-deploy
pipeline:
  mode: fail-closed
checks:
  - name: pii
    type: builtin/pii
    action: redact
""")

        class Args:
            config = config_path
            env = "dev"
            dry_run = True

        # Run from the temp dir
        original_dir = os.getcwd()
        os.chdir(config_dir)
        try:
            result = deploy.run(Args())
            assert result == 0
            assert os.path.exists(os.path.join(config_dir, "infrastructure", "template.yaml"))
        finally:
            os.chdir(original_dir)

    def test_report_generation(self):
        """Report command generates output."""
        import tempfile
        import os
        from guardrailgraph.cli.commands import report

        config_dir = tempfile.mkdtemp()
        config_path = os.path.join(config_dir, "guardrailgraph.yaml")
        with open(config_path, "w") as f:
            f.write("""
project:
  name: test-report
pipeline:
  mode: fail-closed
checks:
  - name: pii
    type: builtin/pii
    action: redact
""")

        output_path = os.path.join(config_dir, "report.json")

        class Args:
            config = config_path
            framework = "general"
            format = "json"
            output = output_path

        result = report.run(Args())
        assert result == 0
        assert os.path.exists(output_path)

        with open(output_path) as f:
            parsed = json.loads(f.read())
            assert parsed["pipeline_name"] == "test-report"
