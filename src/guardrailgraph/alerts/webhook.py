"""Webhook alert notifications for blocked content.

Provides async delivery of alert notifications to Slack, PagerDuty,
and generic webhook endpoints with configurable retry and backoff.
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional
from urllib.request import Request, urlopen
from urllib.error import URLError, HTTPError


class AlertSeverity(str, Enum):
    """Alert severity levels."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class WebhookProvider(str, Enum):
    """Supported webhook providers."""

    SLACK = "slack"
    PAGERDUTY = "pagerduty"
    GENERIC = "generic"


@dataclass
class RetryConfig:
    """Configuration for retry behavior with exponential backoff."""

    max_retries: int = 3
    initial_delay_seconds: float = 1.0
    backoff_multiplier: float = 2.0
    max_delay_seconds: float = 30.0

    def get_delay(self, attempt: int) -> float:
        """Calculate delay for a given retry attempt."""
        delay = self.initial_delay_seconds * (self.backoff_multiplier ** attempt)
        return min(delay, self.max_delay_seconds)


@dataclass
class WebhookChannel:
    """Configuration for a webhook alert channel."""

    name: str
    provider: WebhookProvider
    url: str
    secret: Optional[str] = None
    headers: dict[str, str] = field(default_factory=dict)
    min_severity: AlertSeverity = AlertSeverity.LOW
    retry_config: RetryConfig = field(default_factory=RetryConfig)
    enabled: bool = True
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class AlertEvent:
    """An alert event triggered by blocked content."""

    event_id: str
    rule_name: str
    severity: AlertSeverity
    content_snippet: str
    blocked_reason: str
    timestamp: float = field(default_factory=time.time)
    metadata: dict[str, Any] = field(default_factory=dict)
    tenant_id: Optional[str] = None
    request_id: Optional[str] = None


@dataclass
class DeliveryResult:
    """Result of a webhook delivery attempt."""

    channel_name: str
    success: bool
    status_code: Optional[int] = None
    attempts: int = 1
    error: Optional[str] = None
    duration_ms: float = 0.0


class PayloadFormatter:
    """Formats alert events into provider-specific payloads."""

    def format(self, event: AlertEvent, provider: WebhookProvider) -> dict[str, Any]:
        """Format an alert event for the given provider."""
        if provider == WebhookProvider.SLACK:
            return self._format_slack(event)
        elif provider == WebhookProvider.PAGERDUTY:
            return self._format_pagerduty(event)
        else:
            return self._format_generic(event)

    def _format_slack(self, event: AlertEvent) -> dict[str, Any]:
        """Format as Slack Block Kit message."""
        severity_emoji = {
            AlertSeverity.CRITICAL: ":rotating_light:",
            AlertSeverity.HIGH: ":warning:",
            AlertSeverity.MEDIUM: ":large_orange_circle:",
            AlertSeverity.LOW: ":large_blue_circle:",
            AlertSeverity.INFO: ":information_source:",
        }
        emoji = severity_emoji.get(event.severity, ":bell:")

        return {
            "blocks": [
                {
                    "type": "header",
                    "text": {
                        "type": "plain_text",
                        "text": f"{emoji} Content Blocked: {event.rule_name}",
                    },
                },
                {
                    "type": "section",
                    "fields": [
                        {"type": "mrkdwn", "text": f"*Severity:*\n{event.severity.value}"},
                        {"type": "mrkdwn", "text": f"*Rule:*\n{event.rule_name}"},
                        {"type": "mrkdwn", "text": f"*Reason:*\n{event.blocked_reason}"},
                        {"type": "mrkdwn", "text": f"*Event ID:*\n{event.event_id}"},
                    ],
                },
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": f"*Content Preview:*\n```{event.content_snippet[:200]}```",
                    },
                },
            ],
        }

    def _format_pagerduty(self, event: AlertEvent) -> dict[str, Any]:
        """Format as PagerDuty Events API v2 payload."""
        severity_map = {
            AlertSeverity.CRITICAL: "critical",
            AlertSeverity.HIGH: "error",
            AlertSeverity.MEDIUM: "warning",
            AlertSeverity.LOW: "info",
            AlertSeverity.INFO: "info",
        }

        return {
            "routing_key": "",  # Set by channel config
            "event_action": "trigger",
            "dedup_key": event.event_id,
            "payload": {
                "summary": f"Content blocked by rule: {event.rule_name}",
                "severity": severity_map.get(event.severity, "info"),
                "source": "guardrailgraph",
                "component": event.rule_name,
                "custom_details": {
                    "event_id": event.event_id,
                    "blocked_reason": event.blocked_reason,
                    "content_snippet": event.content_snippet[:500],
                    "tenant_id": event.tenant_id,
                    "request_id": event.request_id,
                },
            },
        }

    def _format_generic(self, event: AlertEvent) -> dict[str, Any]:
        """Format as a generic JSON webhook payload."""
        return {
            "event_type": "content_blocked",
            "event_id": event.event_id,
            "timestamp": event.timestamp,
            "severity": event.severity.value,
            "rule_name": event.rule_name,
            "blocked_reason": event.blocked_reason,
            "content_snippet": event.content_snippet[:500],
            "metadata": {
                "tenant_id": event.tenant_id,
                "request_id": event.request_id,
                **event.metadata,
            },
        }


class WebhookAlertManager:
    """Manages webhook alert channels and dispatches notifications.

    Supports async delivery with retry and exponential backoff.
    Filters alerts by severity per channel.

    Example:
        >>> manager = WebhookAlertManager()
        >>> manager.add_channel(WebhookChannel(
        ...     name="slack-alerts",
        ...     provider=WebhookProvider.SLACK,
        ...     url="https://hooks.slack.com/services/...",
        ...     min_severity=AlertSeverity.HIGH,
        ... ))
        >>> results = await manager.dispatch(alert_event)
    """

    def __init__(self, formatter: Optional[PayloadFormatter] = None) -> None:
        self._channels: dict[str, WebhookChannel] = {}
        self._formatter = formatter or PayloadFormatter()
        self._delivery_history: list[DeliveryResult] = []

    @property
    def channels(self) -> dict[str, WebhookChannel]:
        """Registered channels."""
        return dict(self._channels)

    @property
    def delivery_history(self) -> list[DeliveryResult]:
        """History of delivery attempts."""
        return list(self._delivery_history)

    def add_channel(self, channel: WebhookChannel) -> None:
        """Register a webhook channel."""
        self._channels[channel.name] = channel

    def remove_channel(self, name: str) -> None:
        """Remove a webhook channel."""
        self._channels.pop(name, None)

    def should_alert(self, event: AlertEvent, channel: WebhookChannel) -> bool:
        """Determine if an event should trigger an alert on a channel."""
        if not channel.enabled:
            return False
        severity_order = list(AlertSeverity)
        event_idx = severity_order.index(event.severity)
        min_idx = severity_order.index(channel.min_severity)
        return event_idx <= min_idx

    async def dispatch(self, event: AlertEvent) -> list[DeliveryResult]:
        """Dispatch an alert event to all matching channels.

        Args:
            event: The alert event to dispatch.

        Returns:
            List of delivery results for each channel attempted.
        """
        tasks = []
        for channel in self._channels.values():
            if self.should_alert(event, channel):
                tasks.append(self._deliver_with_retry(event, channel))

        if not tasks:
            return []

        results = await asyncio.gather(*tasks)
        self._delivery_history.extend(results)
        return list(results)

    def dispatch_sync(self, event: AlertEvent) -> list[DeliveryResult]:
        """Synchronous dispatch for non-async contexts."""
        results = []
        for channel in self._channels.values():
            if self.should_alert(event, channel):
                result = self._deliver_sync(event, channel)
                results.append(result)
                self._delivery_history.append(result)
        return results

    async def _deliver_with_retry(
        self, event: AlertEvent, channel: WebhookChannel
    ) -> DeliveryResult:
        """Deliver with retry and exponential backoff."""
        retry_config = channel.retry_config
        last_error: Optional[str] = None
        start_time = time.time()

        for attempt in range(retry_config.max_retries + 1):
            try:
                status_code = await self._send_webhook(event, channel)
                duration_ms = (time.time() - start_time) * 1000
                return DeliveryResult(
                    channel_name=channel.name,
                    success=True,
                    status_code=status_code,
                    attempts=attempt + 1,
                    duration_ms=duration_ms,
                )
            except Exception as e:
                last_error = str(e)
                if attempt < retry_config.max_retries:
                    delay = retry_config.get_delay(attempt)
                    await asyncio.sleep(delay)

        duration_ms = (time.time() - start_time) * 1000
        return DeliveryResult(
            channel_name=channel.name,
            success=False,
            attempts=retry_config.max_retries + 1,
            error=last_error,
            duration_ms=duration_ms,
        )

    def _deliver_sync(self, event: AlertEvent, channel: WebhookChannel) -> DeliveryResult:
        """Synchronous delivery with retry."""
        retry_config = channel.retry_config
        last_error: Optional[str] = None
        start_time = time.time()

        for attempt in range(retry_config.max_retries + 1):
            try:
                status_code = self._send_webhook_sync(event, channel)
                duration_ms = (time.time() - start_time) * 1000
                return DeliveryResult(
                    channel_name=channel.name,
                    success=True,
                    status_code=status_code,
                    attempts=attempt + 1,
                    duration_ms=duration_ms,
                )
            except Exception as e:
                last_error = str(e)
                if attempt < retry_config.max_retries:
                    delay = retry_config.get_delay(attempt)
                    time.sleep(delay)

        duration_ms = (time.time() - start_time) * 1000
        return DeliveryResult(
            channel_name=channel.name,
            success=False,
            attempts=retry_config.max_retries + 1,
            error=last_error,
            duration_ms=duration_ms,
        )

    async def _send_webhook(self, event: AlertEvent, channel: WebhookChannel) -> int:
        """Send webhook request asynchronously."""
        payload = self._formatter.format(event, channel.provider)
        body = json.dumps(payload).encode("utf-8")

        headers = {"Content-Type": "application/json", **channel.headers}
        if channel.secret:
            signature = self._compute_signature(body, channel.secret)
            headers["X-Webhook-Signature"] = signature

        # Use asyncio to run the blocking request in a thread pool
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(
            None, self._do_http_post, channel.url, body, headers
        )

    def _send_webhook_sync(self, event: AlertEvent, channel: WebhookChannel) -> int:
        """Send webhook request synchronously."""
        payload = self._formatter.format(event, channel.provider)
        body = json.dumps(payload).encode("utf-8")

        headers = {"Content-Type": "application/json", **channel.headers}
        if channel.secret:
            signature = self._compute_signature(body, channel.secret)
            headers["X-Webhook-Signature"] = signature

        return self._do_http_post(channel.url, body, headers)

    def _do_http_post(self, url: str, body: bytes, headers: dict[str, str]) -> int:
        """Perform HTTP POST request."""
        req = Request(url, data=body, headers=headers, method="POST")
        try:
            with urlopen(req, timeout=10) as response:
                return response.status
        except HTTPError as e:
            if e.code >= 500:
                raise  # Retry on server errors
            return e.code
        except URLError as e:
            raise ConnectionError(f"Failed to connect: {e.reason}")

    @staticmethod
    def _compute_signature(body: bytes, secret: str) -> str:
        """Compute HMAC-SHA256 signature for webhook payload."""
        return hmac.new(
            secret.encode("utf-8"), body, hashlib.sha256
        ).hexdigest()
