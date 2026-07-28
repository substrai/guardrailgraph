"""Tests for confidence-based routing (block/flag/allow thresholds)."""

from __future__ import annotations

import pytest

from guardrailgraph.core.confidence_router import (
    ConfidenceRouter,
    ReviewQueueItem,
    RoutingConfig,
    RoutingDecision,
    RoutingOutcome,
)


class TestRoutingConfigInit:
    def test_defaults(self):
        config = RoutingConfig()
        assert config.auto_block_threshold == 0.85
        assert config.auto_allow_threshold == 0.20

    def test_custom_thresholds(self):
        config = RoutingConfig(auto_block_threshold=0.9, auto_allow_threshold=0.3)
        assert config.auto_block_threshold == 0.9
        assert config.auto_allow_threshold == 0.3

    def test_flag_range(self):
        config = RoutingConfig(auto_block_threshold=0.9, auto_allow_threshold=0.1)
        assert config.flag_range == (0.1, 0.9)

    def test_invalid_threshold_order(self):
        with pytest.raises(ValueError):
            RoutingConfig(auto_block_threshold=0.3, auto_allow_threshold=0.8)

    def test_equal_thresholds_invalid(self):
        with pytest.raises(ValueError):
            RoutingConfig(auto_block_threshold=0.5, auto_allow_threshold=0.5)


class TestAutoBlock:
    def test_high_confidence_blocks(self):
        router = ConfidenceRouter(RoutingConfig(auto_block_threshold=0.85))
        decision = router.route("toxicity", confidence=0.95, action="block")
        assert decision.outcome == RoutingOutcome.AUTO_BLOCK
        assert decision.is_blocked is True
        assert decision.requires_human_review is False

    def test_exact_block_threshold(self):
        router = ConfidenceRouter(RoutingConfig(auto_block_threshold=0.85))
        decision = router.route("toxicity", confidence=0.85)
        assert decision.outcome == RoutingOutcome.AUTO_BLOCK

    def test_no_review_item_on_block(self):
        router = ConfidenceRouter()
        decision = router.route("check", confidence=0.95)
        assert decision.review_item is None


class TestFlagForReview:
    def test_medium_confidence_flags(self):
        router = ConfidenceRouter(
            RoutingConfig(auto_block_threshold=0.85, auto_allow_threshold=0.20)
        )
        decision = router.route("pii", confidence=0.55)
        assert decision.outcome == RoutingOutcome.FLAG_FOR_REVIEW
        assert decision.is_flagged is True
        assert decision.requires_human_review is True

    def test_review_item_created(self):
        router = ConfidenceRouter()
        decision = router.route("pii", confidence=0.50, original_text="Some text")
        assert decision.review_item is not None
        assert decision.review_item.original_text == "Some text"
        assert decision.review_item.confidence == 0.50

    def test_review_item_added_to_queue(self):
        router = ConfidenceRouter()
        router.route("check", confidence=0.50, original_text="text")
        assert len(router.get_pending_reviews()) == 1


class TestAutoAllow:
    def test_low_confidence_allows(self):
        router = ConfidenceRouter(RoutingConfig(auto_allow_threshold=0.20))
        decision = router.route("toxicity", confidence=0.10)
        assert decision.outcome == RoutingOutcome.AUTO_ALLOW
        assert decision.is_allowed is True
        assert decision.requires_human_review is False

    def test_zero_confidence_allows(self):
        router = ConfidenceRouter()
        decision = router.route("check", confidence=0.0)
        assert decision.outcome == RoutingOutcome.AUTO_ALLOW

    def test_no_review_item_on_allow(self):
        router = ConfidenceRouter()
        decision = router.route("check", confidence=0.05)
        assert decision.review_item is None


class TestBoundaryConditions:
    def test_confidence_clamped_above_1(self):
        router = ConfidenceRouter()
        decision = router.route("check", confidence=1.5)
        assert decision.outcome == RoutingOutcome.AUTO_BLOCK

    def test_confidence_clamped_below_0(self):
        router = ConfidenceRouter()
        decision = router.route("check", confidence=-0.5)
        assert decision.outcome == RoutingOutcome.AUTO_ALLOW


class TestBatchRouting:
    def test_batch_returns_all_decisions(self):
        router = ConfidenceRouter()
        results = [
            {"check_name": "toxicity", "confidence": 0.95, "action": "block"},
            {"check_name": "pii", "confidence": 0.50, "action": "redact"},
            {"check_name": "injection", "confidence": 0.05, "action": "block"},
        ]
        decisions = router.route_batch(results)
        assert len(decisions) == 3
        assert decisions[0].outcome == RoutingOutcome.AUTO_BLOCK
        assert decisions[1].outcome == RoutingOutcome.FLAG_FOR_REVIEW
        assert decisions[2].outcome == RoutingOutcome.AUTO_ALLOW


class TestHumanReviewQueue:
    def test_process_review_allow(self):
        router = ConfidenceRouter()
        decision = router.route("check", confidence=0.50, original_text="text")
        item = decision.review_item
        result = router.process_review_decision(item.item_id, "allow")
        assert result is True
        assert item.reviewed is True
        assert item.reviewer_decision == "allow"

    def test_process_review_block(self):
        router = ConfidenceRouter()
        decision = router.route("check", confidence=0.60)
        item = decision.review_item
        router.process_review_decision(item.item_id, "block")
        assert item.reviewer_decision == "block"

    def test_process_nonexistent_item(self):
        router = ConfidenceRouter()
        result = router.process_review_decision("nonexistent-id", "allow")
        assert result is False

    def test_pending_reviews_filtered(self):
        router = ConfidenceRouter()
        d1 = router.route("c1", confidence=0.50)
        d2 = router.route("c2", confidence=0.55)
        router.process_review_decision(d1.review_item.item_id, "allow")
        pending = router.get_pending_reviews()
        assert len(pending) == 1
        assert pending[0].item_id == d2.review_item.item_id

    def test_queue_size_limit(self):
        router = ConfidenceRouter(RoutingConfig(max_review_queue_size=3))
        for i in range(10):
            router.route(f"check{i}", confidence=0.50)
        assert len(router.review_queue) == 3


class TestStats:
    def test_counters_updated(self):
        router = ConfidenceRouter()
        router.route("a", confidence=0.95)  # block
        router.route("b", confidence=0.50)  # flag
        router.route("c", confidence=0.05)  # allow
        stats = router.get_stats()
        assert stats["auto_block_count"] == 1
        assert stats["flag_for_review_count"] == 1
        assert stats["auto_allow_count"] == 1
        assert stats["total_routed"] == 3

    def test_rates_calculated(self):
        router = ConfidenceRouter()
        router.route("a", confidence=0.95)
        router.route("b", confidence=0.05)
        stats = router.get_stats()
        assert stats["auto_block_rate"] == 0.5
        assert stats["auto_allow_rate"] == 0.5
