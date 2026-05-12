"""Action definitions for guardrail check outcomes."""

from enum import Enum


class Action(str, Enum):
    """Actions that a guardrail check can trigger.

    - PASS: Content is safe, forward to next stage.
    - BLOCK: Content violates policy, reject entirely.
    - REDACT: Content contains sensitive data, modify and forward.
    - FLAG_FOR_REVIEW: Content is borderline, route to human reviewer.
    - LOG: Always log but never block (observability-only).
    """

    PASS = "pass"
    BLOCK = "block"
    REDACT = "redact"
    FLAG_FOR_REVIEW = "flag_for_review"
    LOG = "log"

    def is_blocking(self) -> bool:
        """Return True if this action stops the pipeline."""
        return self == Action.BLOCK

    def is_modifying(self) -> bool:
        """Return True if this action modifies the content."""
        return self == Action.REDACT
