"""Result types for check execution and pipeline outcomes."""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from guardrailgraph.core.actions import Action


@dataclass
class CheckResult:
    """Result of a single guardrail check execution.

    Attributes:
        name: Name of the check that produced this result.
        detected: Whether the check detected a policy violation.
        confidence: Confidence score (0.0 to 1.0) of the detection.
        action: The action taken based on detection and threshold.
        details: Additional details from the check (entities found, etc.).
        latency_ms: Time taken to execute the check in milliseconds.
        redacted_text: Modified text if action is REDACT.
        error: Error message if the check failed to execute.
    """

    name: str
    detected: bool
    confidence: float
    action: Action
    details: Dict[str, Any] = field(default_factory=dict)
    latency_ms: float = 0.0
    redacted_text: Optional[str] = None
    error: Optional[str] = None

    @property
    def passed(self) -> bool:
        """True if the check did not trigger a blocking action."""
        return not self.detected or not self.action.is_blocking()

    @property
    def blocked(self) -> bool:
        """True if the check triggered a block."""
        return self.detected and self.action.is_blocking()

    def to_dict(self) -> Dict[str, Any]:
        """Serialize to dictionary for logging/audit."""
        return {
            "name": self.name,
            "detected": self.detected,
            "confidence": self.confidence,
            "action": self.action.value,
            "details": self.details,
            "latency_ms": self.latency_ms,
            "redacted_text": self.redacted_text,
            "error": self.error,
            "passed": self.passed,
        }


@dataclass
class PipelineResult:
    """Result of executing the full guardrail pipeline.

    Attributes:
        allowed: Whether the content passed all checks.
        action: The final action (most severe action from all checks).
        check_results: Individual results from each check.
        modified_text: The text after all redactions applied.
        original_text: The original input text.
        total_latency_ms: Total pipeline execution time.
        pipeline_name: Name of the pipeline that produced this result.
        metadata: Additional pipeline metadata.
    """

    allowed: bool
    action: Action
    check_results: List[CheckResult] = field(default_factory=list)
    modified_text: Optional[str] = None
    original_text: Optional[str] = None
    total_latency_ms: float = 0.0
    pipeline_name: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)

    @property
    def blocked(self) -> bool:
        """True if the pipeline blocked the content."""
        return not self.allowed

    @property
    def blocking_checks(self) -> List[CheckResult]:
        """Return checks that triggered a block."""
        return [r for r in self.check_results if r.blocked]

    @property
    def flagged_checks(self) -> List[CheckResult]:
        """Return checks that flagged for review."""
        return [
            r for r in self.check_results
            if r.detected and r.action == Action.FLAG_FOR_REVIEW
        ]

    @property
    def redacted_checks(self) -> List[CheckResult]:
        """Return checks that performed redaction."""
        return [
            r for r in self.check_results
            if r.detected and r.action == Action.REDACT
        ]

    def to_dict(self) -> Dict[str, Any]:
        """Serialize to dictionary for logging/audit."""
        return {
            "allowed": self.allowed,
            "action": self.action.value,
            "pipeline_name": self.pipeline_name,
            "total_latency_ms": self.total_latency_ms,
            "check_results": [r.to_dict() for r in self.check_results],
            "modified_text": self.modified_text,
            "metadata": self.metadata,
            "timestamp": time.time(),
        }
