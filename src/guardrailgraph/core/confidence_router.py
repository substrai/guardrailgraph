"""Confidence-based routing with block/flag/allow thresholds.

Three-tier decision system: high confidence → auto-action,
low confidence → human review queue, medium → configurable.

Usage:
    from guardrailgraph.core.confidence_router import ConfidenceRouter, RoutingConfig

    router = ConfidenceRouter(
        config=RoutingConfig(
            auto_block_threshold=0.85,
            auto_allow_threshold=0.20,
            flag_for_review_range=(0.20, 0.85),
        )
    )

    decision = router.route(check_name="toxicity", confidence=0.72, action="block")
    print(decision.outcome)  # "flag_for_review"
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional


class RoutingOutcome(str, Enum):
    """The three-tier routing outcome."""

    AUTO_BLOCK = "auto_block"         # High confidence → immediately block
    FLAG_FOR_REVIEW = "flag_for_review"  # Medium confidence → human queue
    AUTO_ALLOW = "auto_allow"         # Low confidence → pass through
    OVERRIDE = "override"             # Manual override applied


@dataclass
class RoutingConfig:
    """Configuration for confidence-based routing thresholds.

    Args:
        auto_block_threshold: Confidence >= this → auto-block (default 0.85).
        auto_allow_threshold: Confidence <= this → auto-allow (default 0.20).
        flag_for_review_range: (low, high) range for human review.
        review_queue_name: Identifier for the human review queue.
        max_review_queue_size: Maximum items in the review queue.
    """

    auto_block_threshold: float = 0.85
    auto_allow_threshold: float = 0.20
    review_queue_name: str = "default-review"
    max_review_queue_size: int = 1000

    def __post_init__(self):
        if not 0.0 <= self.auto_allow_threshold < self.auto_block_threshold <= 1.0:
            raise ValueError(
                "auto_allow_threshold must be < auto_block_threshold, "
                "both in [0, 1]"
            )

    @property
    def flag_range(self) -> tuple:
        """The (low, high) confidence range that triggers human review."""
        return (self.auto_allow_threshold, self.auto_block_threshold)


@dataclass
class RoutingDecision:
    """The routing decision for a single check result."""

    check_name: str
    confidence: float
    original_action: str
    outcome: RoutingOutcome
    reason: str
    requires_human_review: bool
    review_item: Optional[Dict[str, Any]] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    @property
    def is_blocked(self) -> bool:
        return self.outcome == RoutingOutcome.AUTO_BLOCK

    @property
    def is_flagged(self) -> bool:
        return self.outcome == RoutingOutcome.FLAG_FOR_REVIEW

    @property
    def is_allowed(self) -> bool:
        return self.outcome == RoutingOutcome.AUTO_ALLOW


@dataclass
class ReviewQueueItem:
    """An item queued for human review."""

    item_id: str
    check_name: str
    confidence: float
    original_text: str
    original_action: str
    context: Dict[str, Any] = field(default_factory=dict)
    reviewed: bool = False
    reviewer_decision: Optional[str] = None


class ConfidenceRouter:
    """Routes check results based on confidence thresholds.

    Three-tier system:
    - confidence >= auto_block_threshold → AUTO_BLOCK (immediate action)
    - auto_allow_threshold < confidence < auto_block_threshold → FLAG_FOR_REVIEW
    - confidence <= auto_allow_threshold → AUTO_ALLOW (pass through)

    Args:
        config: Routing threshold configuration.
    """

    def __init__(self, config: Optional[RoutingConfig] = None):
        self._config = config or RoutingConfig()
        self._review_queue: List[ReviewQueueItem] = []
        self._routing_log: List[RoutingDecision] = []
        self._counters: Dict[str, int] = {
            "auto_block": 0,
            "flag_for_review": 0,
            "auto_allow": 0,
        }

    @property
    def config(self) -> RoutingConfig:
        """The routing configuration."""
        return self._config

    @property
    def review_queue(self) -> List[ReviewQueueItem]:
        """Items currently in the review queue."""
        return self._review_queue.copy()

    @property
    def routing_log(self) -> List[RoutingDecision]:
        """All routing decisions made."""
        return self._routing_log.copy()

    @property
    def counters(self) -> Dict[str, int]:
        """Count of decisions by outcome."""
        return self._counters.copy()

    def route(
        self,
        check_name: str,
        confidence: float,
        action: str = "block",
        original_text: str = "",
        context: Optional[Dict[str, Any]] = None,
    ) -> RoutingDecision:
        """Route a check result based on confidence level.

        Args:
            check_name: Name of the check that produced the result.
            confidence: Confidence score (0.0 to 1.0).
            action: The check's configured action (block/redact/flag).
            original_text: The content that was checked.
            context: Additional context for the review item.

        Returns:
            RoutingDecision with outcome and review item if applicable.
        """
        confidence = max(0.0, min(1.0, confidence))

        if confidence >= self._config.auto_block_threshold:
            outcome = RoutingOutcome.AUTO_BLOCK
            reason = (
                f"High confidence ({confidence:.2f} >= {self._config.auto_block_threshold}) "
                f"— auto-applying '{action}'"
            )
            review_item = None
            self._counters["auto_block"] += 1

        elif confidence > self._config.auto_allow_threshold:
            outcome = RoutingOutcome.FLAG_FOR_REVIEW
            reason = (
                f"Medium confidence ({confidence:.2f}) in range "
                f"({self._config.auto_allow_threshold}, {self._config.auto_block_threshold}) "
                f"— routing to human review"
            )
            review_item = self._create_review_item(
                check_name, confidence, original_text, action, context or {}
            )
            self._counters["flag_for_review"] += 1

        else:
            outcome = RoutingOutcome.AUTO_ALLOW
            reason = (
                f"Low confidence ({confidence:.2f} <= {self._config.auto_allow_threshold}) "
                f"— allowing through"
            )
            review_item = None
            self._counters["auto_allow"] += 1

        decision = RoutingDecision(
            check_name=check_name,
            confidence=confidence,
            original_action=action,
            outcome=outcome,
            reason=reason,
            requires_human_review=(outcome == RoutingOutcome.FLAG_FOR_REVIEW),
            review_item=review_item,
            metadata=context or {},
        )

        self._routing_log.append(decision)
        return decision

    def route_batch(
        self,
        results: List[Dict[str, Any]],
    ) -> List[RoutingDecision]:
        """Route multiple check results.

        Args:
            results: List of dicts with 'check_name', 'confidence', 'action'.

        Returns:
            List of RoutingDecision in same order.
        """
        return [
            self.route(
                check_name=r.get("check_name", "unknown"),
                confidence=r.get("confidence", 0.0),
                action=r.get("action", "block"),
                original_text=r.get("text", ""),
                context=r.get("context"),
            )
            for r in results
        ]

    def process_review_decision(
        self,
        item_id: str,
        reviewer_decision: str,
    ) -> bool:
        """Record a human reviewer's decision on a queued item.

        Args:
            item_id: The review item ID.
            reviewer_decision: 'allow', 'block', or 'escalate'.

        Returns:
            True if the item was found and updated.
        """
        for item in self._review_queue:
            if item.item_id == item_id:
                item.reviewed = True
                item.reviewer_decision = reviewer_decision
                return True
        return False

    def get_pending_reviews(self) -> List[ReviewQueueItem]:
        """Get all unreviewed items from the queue."""
        return [item for item in self._review_queue if not item.reviewed]

    def get_stats(self) -> Dict[str, Any]:
        """Get routing statistics."""
        total = sum(self._counters.values())
        return {
            "total_routed": total,
            "auto_block_count": self._counters["auto_block"],
            "flag_for_review_count": self._counters["flag_for_review"],
            "auto_allow_count": self._counters["auto_allow"],
            "auto_block_rate": self._counters["auto_block"] / total if total else 0.0,
            "flag_rate": self._counters["flag_for_review"] / total if total else 0.0,
            "auto_allow_rate": self._counters["auto_allow"] / total if total else 0.0,
            "pending_reviews": len(self.get_pending_reviews()),
        }

    def _create_review_item(
        self,
        check_name: str,
        confidence: float,
        text: str,
        action: str,
        context: Dict[str, Any],
    ) -> ReviewQueueItem:
        """Create and enqueue a review item."""
        import time
        item_id = f"review-{check_name}-{int(time.time() * 1000)}"
        item = ReviewQueueItem(
            item_id=item_id,
            check_name=check_name,
            confidence=confidence,
            original_text=text,
            original_action=action,
            context=context,
        )
        if len(self._review_queue) < self._config.max_review_queue_size:
            self._review_queue.append(item)
        return item
