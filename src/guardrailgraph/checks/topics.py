"""Built-in topic restriction check.

Block or allow specific topics based on keyword matching
and optional semantic similarity scoring.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional, Set

from guardrailgraph.core.actions import Action
from guardrailgraph.core.check import Check, check
from guardrailgraph.core.context import CheckContext


class TopicRestrictor:
    """Configurable topic restriction engine.

    Supports two modes:
    - blocklist: Block specific topics (default).
    - allowlist: Only allow specific topics, block everything else.

    Args:
        blocked_topics: Topics to block.
        allowed_topics: Topics to allow (if set, everything else is blocked).
        mode: "blocklist" or "allowlist".
        case_sensitive: Whether matching is case-sensitive.
        match_mode: "keyword" (substring) or "exact" (whole word).
    """

    def __init__(
        self,
        blocked_topics: Optional[List[str]] = None,
        allowed_topics: Optional[List[str]] = None,
        mode: str = "blocklist",
        case_sensitive: bool = False,
        match_mode: str = "keyword",
    ):
        self.mode = mode
        self.case_sensitive = case_sensitive
        self.match_mode = match_mode

        if mode == "allowlist" and allowed_topics:
            self.allowed_topics = set(
                t if case_sensitive else t.lower() for t in allowed_topics
            )
            self.blocked_topics: Set[str] = set()
        else:
            self.blocked_topics = set(
                t if case_sensitive else t.lower()
                for t in (blocked_topics or [])
            )
            self.allowed_topics: Set[str] = set()

    def evaluate(self, text: str) -> Dict[str, Any]:
        """Evaluate text against topic restrictions.

        Returns:
            Dict with detection result, matched topics, and confidence.
        """
        check_text = text if self.case_sensitive else text.lower()
        matched_topics: List[str] = []

        if self.mode == "blocklist":
            for topic in self.blocked_topics:
                if self._matches(check_text, topic):
                    matched_topics.append(topic)

            return {
                "detected": len(matched_topics) > 0,
                "confidence": 1.0 if matched_topics else 0.0,
                "matched_topics": matched_topics,
                "mode": "blocklist",
            }
        else:
            # Allowlist mode: check if text matches any allowed topic
            for topic in self.allowed_topics:
                if self._matches(check_text, topic):
                    return {
                        "detected": False,
                        "confidence": 0.0,
                        "matched_topics": [topic],
                        "mode": "allowlist",
                    }

            return {
                "detected": True,
                "confidence": 0.8,
                "matched_topics": [],
                "mode": "allowlist",
                "reason": "Content does not match any allowed topic",
            }

    def _matches(self, text: str, topic: str) -> bool:
        """Check if topic appears in text."""
        if self.match_mode == "exact":
            pattern = r"\b" + re.escape(topic) + r"\b"
            return bool(re.search(pattern, text))
        else:
            return topic in text

    def to_check(
        self,
        name: str = "topic-restriction",
        action: Action = Action.BLOCK,
        threshold: float = 0.5,
    ) -> Check:
        """Convert this restrictor into a Check instance."""
        restrictor = self

        @check(name=name, action=action, threshold=threshold)
        def _topic_check(text: str) -> dict:
            return restrictor.evaluate(text)

        return _topic_check


def topic_check(
    blocked_topics: Optional[List[str]] = None,
    allowed_topics: Optional[List[str]] = None,
    mode: str = "blocklist",
    action: Action = Action.BLOCK,
    threshold: float = 0.5,
    name: str = "topic-restriction",
) -> Check:
    """Create a topic restriction check.

    Args:
        blocked_topics: Topics to block.
        allowed_topics: Topics to allow (blocklist mode ignores this).
        mode: "blocklist" or "allowlist".
        action: Action when restricted topic detected.
        threshold: Confidence threshold.
        name: Check name.

    Returns:
        Configured Check instance.

    Example:
        from guardrailgraph.checks import topic_check

        my_topics = topic_check(
            blocked_topics=["weapons", "illegal activities", "medical diagnosis"],
            action=Action.BLOCK,
        )
    """
    restrictor = TopicRestrictor(
        blocked_topics=blocked_topics,
        allowed_topics=allowed_topics,
        mode=mode,
    )
    return restrictor.to_check(name=name, action=action, threshold=threshold)
