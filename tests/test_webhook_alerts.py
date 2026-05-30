"""Tests for webhook alert notifications."""

import asyncio
import json
import time
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from guardrailgraph.alerts.webhook import (
    AlertEvent,
    AlertSeverity,
    DeliveryResult,
    PayloadFormatter,
    RetryConfig,
    WebhookAlertManager,
    WebhookChannel,
    WebhookProvider,
)


@pytest.fixture
def sample_event() -> AlertEvent:
    """Create a sample alert event."""
    return AlertEvent(
        event_id="evt-001",
        rule_name="pii_detection",
        severity=AlertSeverity.HIGH,
        content_snippet="User SSN: 123-45-6789 was detected",
        blocked_reason="PII detected in output",
        tenant_id="tenant-abc",
        request_id="req-xyz",
    )


@pytest.fixture
def slack_channel() -> WebhookChannel:
    """Create a Slack webhook channel."""
    return WebhookChannel(
        name="slack-security",
        provider=WebhookProvider.SLACK,
        url="https://hooks.slack.com/services/T00/B00/xxx",
        min_severity=AlertSeverity.MEDIUM,
    )


@pytest.fixture
def pagerduty_channel() -> WebhookChannel:
    """Create a PagerDuty webhook channel."""
    return WebhookChannel(
        name="pagerduty-critical",
        provider=WebhookProvider.PAGERDUTY,
        url="https://events.pagerduty.com/v2/enqueue",
        min_severity=AlertSeverity.CRITICAL,
    )


@pytest.fixture
def generic_channel() -> WebhookChannel:
    """Create a generic webhook channel."""
    return WebhookChannel(
        name="generic-all",
        provider=WebhookProvider.GENERIC,
        url="https://example.com/webhook",
        secret="my-secret-key",
        min_severity=AlertSeverity.LOW,
    )


@pytest.fixture
def manager() -> WebhookAlertManager:
    """Create a webhook alert manager."""
    return WebhookAlertManager()


class TestPayloadFormatter:
    """Test payload formatting for different providers."""

    def test_slack_payload_format(self, sample_event: AlertEvent) -> None:
        """Should format Slack payload with blocks."""
        formatter = PayloadFormatter()
        payload = formatter.format(sample_event, WebhookProvider.SLACK)

        assert "blocks" in payload
        assert len(payload["blocks"]) >= 2
        # Header block should contain rule name
        header = payload["blocks"][0]
        assert header["type"] == "header"
        assert "pii_detection" in header["text"]["text"]

    def test_pagerduty_payload_format(self, sample_event: AlertEvent) -> None:
        """Should format PagerDuty Events API v2 payload."""
        formatter = PayloadFormatter()
        payload = formatter.format(sample_event, WebhookProvider.PAGERDUTY)

        assert payload["event_action"] == "trigger"
        assert payload["dedup_key"] == "evt-001"
        assert "payload" in payload
        assert payload["payload"]["severity"] == "error"  # HIGH maps to error
        assert "pii_detection" in payload["payload"]["summary"]

    def test_generic_payload_format(self, sample_event: AlertEvent) -> None:
        """Should format generic JSON payload."""
        formatter = PayloadFormatter()
        payload = formatter.format(sample_event, WebhookProvider.GENERIC)

        assert payload["event_type"] == "content_blocked"
        assert payload["event_id"] == "evt-001"
        assert payload["severity"] == "high"
        assert payload["rule_name"] == "pii_detection"
        assert payload["metadata"]["tenant_id"] == "tenant-abc"


class TestSeverityFiltering:
    """Test severity-based alert filtering."""

    def test_should_alert_matching_severity(
        self, manager: WebhookAlertManager, sample_event: AlertEvent, slack_channel: WebhookChannel
    ) -> None:
        """Should alert when event severity meets channel minimum."""
        # HIGH event, MEDIUM minimum -> should alert
        assert manager.should_alert(sample_event, slack_channel) is True

    def test_should_not_alert_below_severity(
        self, manager: WebhookAlertManager, slack_channel: WebhookChannel
    ) -> None:
        """Should not alert when event severity is below channel minimum."""
        low_event = AlertEvent(
            event_id="evt-002",
            rule_name="info_log",
            severity=AlertSeverity.INFO,
            content_snippet="Normal content",
            blocked_reason="Informational",
        )
        # INFO event, MEDIUM minimum -> should not alert
        assert manager.should_alert(low_event, slack_channel) is False

    def test_disabled_channel_never_alerts(
        self, manager: WebhookAlertManager, sample_event: AlertEvent, slack_channel: WebhookChannel
    ) -> None:
        """Should not alert on disabled channels."""
        slack_channel.enabled = False
        assert manager.should_alert(sample_event, slack_channel) is False


class TestRetryConfig:
    """Test retry configuration and backoff calculation."""

    def test_exponential_backoff_calculation(self) -> None:
        """Should calculate exponential backoff delays."""
        config = RetryConfig(
            initial_delay_seconds=1.0,
            backoff_multiplier=2.0,
            max_delay_seconds=30.0,
        )
        assert config.get_delay(0) == 1.0
        assert config.get_delay(1) == 2.0
        assert config.get_delay(2) == 4.0
        assert config.get_delay(3) == 8.0

    def test_backoff_respects_max_delay(self) -> None:
        """Should cap delay at max_delay_seconds."""
        config = RetryConfig(
            initial_delay_seconds=1.0,
            backoff_multiplier=2.0,
            max_delay_seconds=5.0,
        )
        assert config.get_delay(10) == 5.0  # Would be 1024 without cap


class TestWebhookAlertManager:
    """Test the alert manager dispatch logic."""

    def test_add_and_remove_channel(
        self, manager: WebhookAlertManager, slack_channel: WebhookChannel
    ) -> None:
        """Should add and remove channels."""
        manager.add_channel(slack_channel)
        assert "slack-security" in manager.channels

        manager.remove_channel("slack-security")
        assert "slack-security" not in manager.channels

    def test_dispatch_sync_success(
        self, manager: WebhookAlertManager, generic_channel: WebhookChannel, sample_event: AlertEvent
    ) -> None:
        """Should deliver successfully via sync dispatch."""
        manager.add_channel(generic_channel)

        with patch.object(manager, "_do_http_post", return_value=200):
            results = manager.dispatch_sync(sample_event)

        assert len(results) == 1
        assert results[0].success is True
        assert results[0].status_code == 200
        assert results[0].channel_name == "generic-all"

    def test_dispatch_sync_retry_on_failure(
        self, manager: WebhookAlertManager, generic_channel: WebhookChannel, sample_event: AlertEvent
    ) -> None:
        """Should retry on failure with backoff."""
        generic_channel.retry_config = RetryConfig(
            max_retries=2, initial_delay_seconds=0.01
        )
        manager.add_channel(generic_channel)

        call_count = 0

        def mock_post(*args, **kwargs):
            nonlocal call_count
            call_count += 1
            if call_count < 3:
                raise ConnectionError("Connection refused")
            return 200

        with patch.object(manager, "_do_http_post", side_effect=mock_post):
            results = manager.dispatch_sync(sample_event)

        assert len(results) == 1
        assert results[0].success is True
        assert results[0].attempts == 3

    def test_dispatch_filters_by_severity(
        self,
        manager: WebhookAlertManager,
        pagerduty_channel: WebhookChannel,
        slack_channel: WebhookChannel,
        sample_event: AlertEvent,
    ) -> None:
        """Should only dispatch to channels matching severity."""
        manager.add_channel(pagerduty_channel)  # CRITICAL only
        manager.add_channel(slack_channel)  # MEDIUM and above

        with patch.object(manager, "_do_http_post", return_value=200):
            results = manager.dispatch_sync(sample_event)  # HIGH severity

        # Only slack should receive (HIGH >= MEDIUM), not pagerduty (HIGH < CRITICAL)
        assert len(results) == 1
        assert results[0].channel_name == "slack-security"

    def test_delivery_history_tracking(
        self, manager: WebhookAlertManager, generic_channel: WebhookChannel, sample_event: AlertEvent
    ) -> None:
        """Should track delivery history."""
        manager.add_channel(generic_channel)

        with patch.object(manager, "_do_http_post", return_value=200):
            manager.dispatch_sync(sample_event)
            manager.dispatch_sync(sample_event)

        assert len(manager.delivery_history) == 2
