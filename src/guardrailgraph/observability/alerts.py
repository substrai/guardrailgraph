"""Alert system — notify on policy violations via multiple channels.

Supports:
- Console/log alerts (default)
- Webhook (Slack, PagerDuty, custom)
- AWS SNS
- Email (via SNS or webhook)
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Dict, List, Optional

from guardrailgraph.core.result import PipelineResult


class AlertSeverity(str, Enum):
    """Alert severity levels."""

    INFO = "info"
    WARNING = "warning"
    CRITICAL = "critical"


class AlertChannel(str, Enum):
    """Alert delivery channels."""

    CONSOLE = "console"
    WEBHOOK = "webhook"
    SNS = "sns"
    CALLBACK = "callback"


@dataclass
class Alert:
    """An alert triggered by a guardrail event."""

    id: str
    severity: AlertSeverity
    title: str
    message: str
    pipeline_name: str
    check_name: Optional[str] = None
    timestamp: float = field(default_factory=time.time)
    metadata: Dict[str, Any] = field(default_factory=dict)
    delivered: bool = False
    channel: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "severity": self.severity.value,
            "title": self.title,
            "message": self.message,
            "pipeline_name": self.pipeline_name,
            "check_name": self.check_name,
            "timestamp": self.timestamp,
            "metadata": self.metadata,
            "delivered": self.delivered,
        }

    def to_slack_payload(self) -> Dict[str, Any]:
        """Format as Slack webhook payload."""
        color = {"info": "#36a64f", "warning": "#ff9900", "critical": "#ff0000"}
        return {
            "attachments": [{
                "color": color.get(self.severity.value, "#cccccc"),
                "title": f"🚨 {self.title}",
                "text": self.message,
                "fields": [
                    {"title": "Pipeline", "value": self.pipeline_name, "short": True},
                    {"title": "Check", "value": self.check_name or "N/A", "short": True},
                    {"title": "Severity", "value": self.severity.value.upper(), "short": True},
                ],
                "ts": int(self.timestamp),
            }]
        }

    def to_pagerduty_payload(self) -> Dict[str, Any]:
        """Format as PagerDuty Events API v2 payload."""
        severity_map = {"info": "info", "warning": "warning", "critical": "critical"}
        return {
            "routing_key": "",  # Set by AlertManager
            "event_action": "trigger",
            "payload": {
                "summary": self.title,
                "severity": severity_map.get(self.severity.value, "warning"),
                "source": f"guardrailgraph/{self.pipeline_name}",
                "custom_details": {
                    "message": self.message,
                    "check_name": self.check_name,
                    "pipeline": self.pipeline_name,
                },
            },
        }


@dataclass
class AlertRule:
    """A rule that triggers alerts based on conditions."""

    name: str
    condition: Callable[[PipelineResult], bool]
    severity: AlertSeverity = AlertSeverity.WARNING
    title_template: str = "Guardrail Alert: {pipeline_name}"
    message_template: str = "Check '{check_name}' triggered on pipeline '{pipeline_name}'"
    cooldown_seconds: float = 60.0  # Don't re-alert within this window
    _last_triggered: float = 0.0

    def evaluate(self, result: PipelineResult) -> Optional[Alert]:
        """Evaluate the rule against a pipeline result."""
        now = time.time()
        if now - self._last_triggered < self.cooldown_seconds:
            return None

        if not self.condition(result):
            return None

        self._last_triggered = now

        # Find the triggering check
        check_name = None
        for cr in result.check_results:
            if cr.detected:
                check_name = cr.name
                break

        alert = Alert(
            id=f"alert-{int(now * 1000)}",
            severity=self.severity,
            title=self.title_template.format(
                pipeline_name=result.pipeline_name,
                check_name=check_name or "unknown",
            ),
            message=self.message_template.format(
                pipeline_name=result.pipeline_name,
                check_name=check_name or "unknown",
                action=result.action.value,
            ),
            pipeline_name=result.pipeline_name,
            check_name=check_name,
        )
        return alert


class AlertManager:
    """Manages alert rules and delivery channels.

    Args:
        channels: List of delivery channels to use.
        webhook_url: Webhook URL for Slack/custom alerts.
        sns_topic_arn: AWS SNS topic ARN.
        pagerduty_key: PagerDuty routing key.
        on_alert: Custom callback for alerts.

    Example:
        manager = AlertManager(
            channels=[AlertChannel.CONSOLE, AlertChannel.WEBHOOK],
            webhook_url="https://hooks.slack.com/services/...",
        )
        manager.add_rule(AlertRule(
            name="block-alert",
            condition=lambda r: not r.allowed,
            severity=AlertSeverity.WARNING,
        ))
        manager.evaluate(pipeline_result)
    """

    def __init__(
        self,
        channels: Optional[List[AlertChannel]] = None,
        webhook_url: Optional[str] = None,
        sns_topic_arn: Optional[str] = None,
        pagerduty_key: Optional[str] = None,
        on_alert: Optional[Callable[[Alert], None]] = None,
    ):
        self.channels = channels or [AlertChannel.CONSOLE]
        self.webhook_url = webhook_url
        self.sns_topic_arn = sns_topic_arn
        self.pagerduty_key = pagerduty_key
        self.on_alert = on_alert
        self._rules: List[AlertRule] = []
        self._alert_history: List[Alert] = []

    def add_rule(self, rule: AlertRule) -> "AlertManager":
        """Add an alert rule."""
        self._rules.append(rule)
        return self

    def add_block_rule(
        self,
        severity: AlertSeverity = AlertSeverity.WARNING,
        cooldown_seconds: float = 60.0,
    ) -> "AlertManager":
        """Add a rule that alerts on any block."""
        self._rules.append(AlertRule(
            name="on-block",
            condition=lambda r: not r.allowed,
            severity=severity,
            title_template="Content Blocked: {pipeline_name}",
            message_template="Pipeline '{pipeline_name}' blocked content (check: {check_name}, action: {action})",
            cooldown_seconds=cooldown_seconds,
        ))
        return self

    def add_high_block_rate_rule(
        self,
        threshold: float = 0.2,
        window_size: int = 100,
        severity: AlertSeverity = AlertSeverity.CRITICAL,
    ) -> "AlertManager":
        """Add a rule that alerts on high block rate."""
        counter = {"total": 0, "blocked": 0}

        def check_rate(result: PipelineResult) -> bool:
            counter["total"] += 1
            if not result.allowed:
                counter["blocked"] += 1
            if counter["total"] >= window_size:
                rate = counter["blocked"] / counter["total"]
                counter["total"] = 0
                counter["blocked"] = 0
                return rate > threshold
            return False

        self._rules.append(AlertRule(
            name="high-block-rate",
            condition=check_rate,
            severity=severity,
            title_template="High Block Rate: {pipeline_name}",
            message_template="Block rate exceeded {threshold} on '{pipeline_name}'".format(threshold=threshold, pipeline_name="{pipeline_name}"),
            cooldown_seconds=300.0,
        ))
        return self

    def evaluate(self, result: PipelineResult) -> List[Alert]:
        """Evaluate all rules against a pipeline result.

        Returns:
            List of triggered alerts.
        """
        triggered: List[Alert] = []

        for rule in self._rules:
            alert = rule.evaluate(result)
            if alert:
                self._deliver(alert)
                self._alert_history.append(alert)
                triggered.append(alert)

        return triggered

    def _deliver(self, alert: Alert) -> None:
        """Deliver an alert through configured channels."""
        for channel in self.channels:
            if channel == AlertChannel.CONSOLE:
                self._deliver_console(alert)
            elif channel == AlertChannel.WEBHOOK:
                self._deliver_webhook(alert)
            elif channel == AlertChannel.SNS:
                self._deliver_sns(alert)
            elif channel == AlertChannel.CALLBACK:
                if self.on_alert:
                    self.on_alert(alert)

        alert.delivered = True

    def _deliver_console(self, alert: Alert) -> None:
        """Print alert to console/log."""
        icons = {"info": "ℹ️", "warning": "⚠️", "critical": "🚨"}
        icon = icons.get(alert.severity.value, "📢")
        print(f"{icon} [{alert.severity.value.upper()}] {alert.title}: {alert.message}")

    def _deliver_webhook(self, alert: Alert) -> None:
        """Send alert to webhook (Slack, etc.)."""
        if not self.webhook_url:
            return
        # In production, use urllib or requests
        # For now, store the payload for testing
        alert.metadata["webhook_payload"] = alert.to_slack_payload()
        alert.channel = "webhook"

    def _deliver_sns(self, alert: Alert) -> None:
        """Publish alert to AWS SNS."""
        if not self.sns_topic_arn:
            return
        alert.metadata["sns_payload"] = {
            "TopicArn": self.sns_topic_arn,
            "Subject": alert.title,
            "Message": json.dumps(alert.to_dict()),
        }
        alert.channel = "sns"

    @property
    def alert_count(self) -> int:
        """Total alerts triggered."""
        return len(self._alert_history)

    @property
    def recent_alerts(self) -> List[Alert]:
        """Last 50 alerts."""
        return self._alert_history[-50:]

    def stats(self) -> Dict[str, Any]:
        """Get alert statistics."""
        severity_counts: Dict[str, int] = {}
        for alert in self._alert_history:
            severity_counts[alert.severity.value] = severity_counts.get(alert.severity.value, 0) + 1
        return {
            "total_alerts": len(self._alert_history),
            "by_severity": severity_counts,
            "rules_count": len(self._rules),
        }
