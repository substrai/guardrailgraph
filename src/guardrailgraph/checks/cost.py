"""Built-in cost limiting check.

Enforces token and cost limits per request/session to prevent
runaway spending on LLM API calls.
"""

from __future__ import annotations

import re
from typing import Any, Dict, Optional

from guardrailgraph.core.actions import Action
from guardrailgraph.core.check import Check, check
from guardrailgraph.core.context import CheckContext


# Approximate token estimation (4 chars per token for English)
CHARS_PER_TOKEN = 4


class CostLimiter:
    """Configurable cost limiting engine.

    Args:
        max_tokens_per_request: Maximum tokens allowed per request.
        max_cost_per_request: Maximum cost in USD per request.
        max_tokens_per_session: Maximum tokens per session.
        cost_per_1k_input_tokens: Cost per 1K input tokens.
        cost_per_1k_output_tokens: Cost per 1K output tokens.
    """

    def __init__(
        self,
        max_tokens_per_request: int = 4000,
        max_cost_per_request: float = 0.10,
        max_tokens_per_session: Optional[int] = None,
        cost_per_1k_input_tokens: float = 0.00025,
        cost_per_1k_output_tokens: float = 0.00125,
    ):
        self.max_tokens_per_request = max_tokens_per_request
        self.max_cost_per_request = max_cost_per_request
        self.max_tokens_per_session = max_tokens_per_session
        self.cost_per_1k_input_tokens = cost_per_1k_input_tokens
        self.cost_per_1k_output_tokens = cost_per_1k_output_tokens

    def estimate_tokens(self, text: str) -> int:
        """Estimate token count from text length."""
        return max(1, len(text) // CHARS_PER_TOKEN)

    def estimate_cost(self, token_count: int) -> float:
        """Estimate cost for a given token count (input only)."""
        return (token_count / 1000) * self.cost_per_1k_input_tokens

    def evaluate(self, text: str, context: Optional[CheckContext] = None) -> Dict[str, Any]:
        """Evaluate text against cost limits.

        Returns:
            Dict with detection result and cost estimates.
        """
        estimated_tokens = self.estimate_tokens(text)
        estimated_cost = self.estimate_cost(estimated_tokens)

        # Check token limit
        token_exceeded = estimated_tokens > self.max_tokens_per_request
        cost_exceeded = estimated_cost > self.max_cost_per_request

        detected = token_exceeded or cost_exceeded

        return {
            "detected": detected,
            "confidence": 1.0 if detected else 0.0,
            "estimated_tokens": estimated_tokens,
            "estimated_cost_usd": estimated_cost,
            "max_tokens": self.max_tokens_per_request,
            "max_cost_usd": self.max_cost_per_request,
            "token_exceeded": token_exceeded,
            "cost_exceeded": cost_exceeded,
        }

    def to_check(
        self,
        name: str = "cost-limit",
        action: Action = Action.BLOCK,
        threshold: float = 0.5,
    ) -> Check:
        """Convert this limiter into a Check instance."""
        limiter = self

        @check(name=name, action=action, threshold=threshold)
        def _cost_check(text: str) -> dict:
            return limiter.evaluate(text)

        return _cost_check


def cost_check(
    max_tokens_per_request: int = 4000,
    max_cost_per_request: float = 0.10,
    action: Action = Action.BLOCK,
    threshold: float = 0.5,
    name: str = "cost-limit",
) -> Check:
    """Create a cost limiting check.

    Args:
        max_tokens_per_request: Maximum tokens per request.
        max_cost_per_request: Maximum cost in USD per request.
        action: Action when limit exceeded.
        threshold: Confidence threshold.
        name: Check name.

    Returns:
        Configured Check instance.

    Example:
        from guardrailgraph.checks import cost_check

        my_cost = cost_check(max_tokens_per_request=2000)
    """
    limiter = CostLimiter(
        max_tokens_per_request=max_tokens_per_request,
        max_cost_per_request=max_cost_per_request,
    )
    return limiter.to_check(name=name, action=action, threshold=threshold)
