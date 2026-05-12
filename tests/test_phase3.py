"""Tests for Phase 3 — Advanced Safety Features."""

import pytest
from guardrailgraph import pipeline, check, Action, ab_test, ReviewQueue, Pipeline
from guardrailgraph.checks import (
    hallucination_check, semantic_similarity_check, language_check,
)
from guardrailgraph.observability.analytics import GuardrailAnalytics


class TestHallucinationCheck:
    """Test hallucination detection."""

    def test_detects_fabricated_citations(self):
        """Detect fabricated research citations."""
        hc = hallucination_check(method="indicators", threshold=0.3)
        result = hc("According to a 2023 study by Harvard researchers, this is proven fact.")
        assert result.detected is True
        assert result.confidence > 0

    def test_detects_overly_confident_claims(self):
        """Detect overly confident unsupported claims."""
        hc = hallucination_check(method="indicators", threshold=0.3)
        result = hc("It is a well-known fact that studies have conclusively shown this to be true.")
        assert result.detected is True

    def test_passes_hedged_responses(self):
        """Hedged responses reduce hallucination risk."""
        hc = hallucination_check(method="indicators", threshold=0.5)
        result = hc("I'm not sure about this, but it's possible that the answer is 42. Please verify this information.")
        assert result.detected is False

    def test_safe_text_passes(self):
        """Normal text without hallucination indicators passes."""
        hc = hallucination_check(threshold=0.5)
        result = hc("The weather today is sunny with a high of 75 degrees.")
        assert result.detected is False

    def test_grounding_with_sources(self):
        """Grounding check against provided sources."""
        sources = [
            "Python is a programming language created by Guido van Rossum.",
            "Python was first released in 1991.",
        ]
        hc = hallucination_check(
            method="grounding",
            knowledge_base=sources,
            threshold=0.5,
        )
        # Text grounded in sources
        result = hc("Python is a programming language released in 1991.")
        # Should have good grounding score
        assert result.details.get("grounding_score", 0) > 0


class TestSemanticSimilarityCheck:
    """Test semantic similarity detection."""

    def test_detects_similar_text(self):
        """Detect text too similar to protected content."""
        protected = "The quick brown fox jumps over the lazy dog in the sunny meadow by the river"
        sc = semantic_similarity_check(
            protected_texts=[protected],
            similarity_threshold=0.5,
        )
        # Very similar text
        result = sc("The quick brown fox jumps over the lazy dog in the sunny meadow by the stream")
        assert result.detected is True
        assert result.confidence > 0.5

    def test_passes_different_text(self):
        """Different text passes similarity check."""
        protected = "The quick brown fox jumps over the lazy dog in the sunny meadow"
        sc = semantic_similarity_check(
            protected_texts=[protected],
            similarity_threshold=0.7,
        )
        result = sc("Machine learning algorithms process data to find patterns and make predictions")
        assert result.detected is False

    def test_short_text_skipped(self):
        """Short text is skipped (below min length)."""
        sc = semantic_similarity_check(
            protected_texts=["Some protected content here"],
            similarity_threshold=0.5,
        )
        result = sc("Hello")
        assert result.detected is False

    def test_no_protected_texts(self):
        """No protected texts means nothing to compare against."""
        sc = semantic_similarity_check(protected_texts=[], similarity_threshold=0.5)
        result = sc("Any text here that is long enough to be checked by the system")
        assert result.detected is False


class TestLanguageCheck:
    """Test multi-language support."""

    def test_detects_english(self):
        """Detect English text."""
        from guardrailgraph.checks.language import LanguageDetector
        detector = LanguageDetector()
        langs = detector.detect_language("The quick brown fox jumps over the lazy dog")
        assert "en" in langs
        assert langs["en"] > 0.2

    def test_detects_spanish(self):
        """Detect Spanish text."""
        from guardrailgraph.checks.language import LanguageDetector
        detector = LanguageDetector()
        langs = detector.detect_language("El gato está en la casa con los niños")
        assert "es" in langs

    def test_allowlist_blocks_non_allowed(self):
        """Allowlist mode blocks non-allowed languages."""
        lc = language_check(allowed_languages=["en"], mode="allowlist")
        # Spanish text
        result = lc("El gato está en la casa con los niños para comer")
        assert result.detected is True

    def test_allowlist_passes_allowed(self):
        """Allowlist mode passes allowed languages."""
        lc = language_check(allowed_languages=["en"], mode="allowlist")
        result = lc("The cat is in the house with the children for dinner")
        assert result.detected is False

    def test_blocklist_blocks_specified(self):
        """Blocklist mode blocks specified languages."""
        lc = language_check(blocked_languages=["es"], mode="blocklist")
        result = lc("El gato está en la casa con los niños para comer")
        assert result.detected is True


class TestABTesting:
    """Test A/B testing for guardrail configurations."""

    def _make_pipelines(self):
        @check(name="strict", action=Action.BLOCK, threshold=0.3)
        def strict_check(text: str) -> dict:
            return {"detected": "bad" in text, "confidence": 0.5}

        @check(name="relaxed", action=Action.BLOCK, threshold=0.9)
        def relaxed_check(text: str) -> dict:
            return {"detected": "bad" in text, "confidence": 0.5}

        strict = pipeline(name="strict", checks=[strict_check])
        relaxed = pipeline(name="relaxed", checks=[relaxed_check])
        return strict, relaxed

    def test_ab_test_creation(self):
        """Create an A/B test."""
        strict, relaxed = self._make_pipelines()
        test = ab_test(
            name="threshold-test",
            variants={"strict": (strict, 0.5), "relaxed": (relaxed, 0.5)},
        )
        assert test.name == "threshold-test"

    def test_ab_test_runs(self):
        """A/B test executes and returns result."""
        strict, relaxed = self._make_pipelines()
        test = ab_test(
            name="test",
            variants={"strict": (strict, 0.5), "relaxed": (relaxed, 0.5)},
        )
        result = test.run("hello world")
        assert result.active_variant in ("strict", "relaxed")
        assert result.result is not None

    def test_ab_test_sticky_routing(self):
        """Sticky routing gives same user same variant."""
        strict, relaxed = self._make_pipelines()
        test = ab_test(
            name="test",
            variants={"strict": (strict, 0.5), "relaxed": (relaxed, 0.5)},
            sticky=True,
        )
        # Same user should get same variant
        r1 = test.run("text1", user_id="user-123")
        r2 = test.run("text2", user_id="user-123")
        assert r1.active_variant == r2.active_variant

    def test_ab_test_metrics(self):
        """A/B test collects metrics."""
        strict, relaxed = self._make_pipelines()
        test = ab_test(
            name="test",
            variants={"strict": (strict, 1.0), "relaxed": (relaxed, 0.0)},
        )
        # All traffic to strict
        for _ in range(10):
            test.run("safe text")

        metrics = test.get_metrics()
        assert metrics["strict"].total_requests == 10

    def test_ab_test_shadow_mode(self):
        """Shadow mode runs all variants."""
        strict, relaxed = self._make_pipelines()
        test = ab_test(
            name="test",
            variants={"strict": (strict, 1.0), "relaxed": (relaxed, 0.0)},
            shadow_mode=True,
        )
        result = test.run("bad text")
        assert "strict" in result.all_variants
        assert "relaxed" in result.all_variants


class TestHumanReview:
    """Test human-in-the-loop review system."""

    def test_submit_review(self):
        """Submit content for human review."""
        @check(name="flagger", action=Action.FLAG_FOR_REVIEW)
        def flag_check(text: str) -> dict:
            return {"detected": True, "confidence": 0.7}

        p = pipeline(name="test", checks=[flag_check])
        result = p.run("borderline content")

        queue = ReviewQueue(timeout_hours=24)
        request = queue.submit(result, reason="Needs human review")

        assert request.id is not None
        assert request.status.value == "pending"
        assert queue.pending_count == 1

    def test_approve_review(self):
        """Approve a review request."""
        @check(name="flagger", action=Action.FLAG_FOR_REVIEW)
        def flag_check(text: str) -> dict:
            return {"detected": True, "confidence": 0.7}

        p = pipeline(name="test", checks=[flag_check])
        result = p.run("content")

        queue = ReviewQueue()
        request = queue.submit(result)
        approved = queue.approve(request.id, reviewer_id="reviewer@test.com")

        assert approved.status.value == "approved"
        assert approved.reviewer_id == "reviewer@test.com"

    def test_reject_review(self):
        """Reject a review request."""
        @check(name="flagger", action=Action.FLAG_FOR_REVIEW)
        def flag_check(text: str) -> dict:
            return {"detected": True, "confidence": 0.7}

        p = pipeline(name="test", checks=[flag_check])
        result = p.run("content")

        queue = ReviewQueue()
        request = queue.submit(result)
        rejected = queue.reject(request.id, notes="Confirmed unsafe")

        assert rejected.status.value == "rejected"

    def test_queue_stats(self):
        """Queue provides statistics."""
        @check(name="flagger", action=Action.FLAG_FOR_REVIEW)
        def flag_check(text: str) -> dict:
            return {"detected": True, "confidence": 0.7}

        p = pipeline(name="test", checks=[flag_check])
        queue = ReviewQueue()

        for i in range(5):
            result = p.run(f"content {i}")
            queue.submit(result)

        queue.approve(queue.get_pending()[0].id)
        queue.reject(queue.get_pending()[0].id)

        stats = queue.stats()
        assert stats["total"] == 5
        assert stats["approved"] == 1
        assert stats["rejected"] == 1
        assert stats["pending"] == 3

    def test_on_approve_callback(self):
        """Callback fires on approval."""
        callbacks = []

        @check(name="flagger", action=Action.FLAG_FOR_REVIEW)
        def flag_check(text: str) -> dict:
            return {"detected": True, "confidence": 0.7}

        p = pipeline(name="test", checks=[flag_check])
        queue = ReviewQueue(on_approve=lambda r: callbacks.append(r.id))

        result = p.run("content")
        request = queue.submit(result)
        queue.approve(request.id)

        assert len(callbacks) == 1


class TestGuardrailAnalytics:
    """Test guardrail analytics engine."""

    def test_record_results(self):
        """Analytics records pipeline results."""
        analytics = GuardrailAnalytics()

        @check(name="test-check", action=Action.BLOCK)
        def test_check(text: str) -> dict:
            return {"detected": "bad" in text, "confidence": 0.9}

        p = pipeline(name="test", checks=[test_check])

        # Record some results
        for text in ["hello", "world", "bad text", "good text", "bad again"]:
            result = p.run(text)
            analytics.record(result)

        summary = analytics.summary()
        assert summary["total_requests"] == 5
        assert summary["blocked"] == 2
        assert summary["passed"] == 3
        assert summary["block_rate"] == pytest.approx(0.4)

    def test_check_analytics(self):
        """Per-check analytics are tracked."""
        analytics = GuardrailAnalytics()

        @check(name="my-check", action=Action.BLOCK)
        def my_check(text: str) -> dict:
            return {"detected": "x" in text, "confidence": 0.8}

        p = pipeline(name="test", checks=[my_check])

        for text in ["x", "y", "x", "y", "y"]:
            analytics.record(p.run(text))

        check_info = analytics.check_summary("my-check")
        assert check_info is not None
        assert check_info["total_executions"] == 5
        assert check_info["detections"] == 2
        assert check_info["detection_rate"] == pytest.approx(0.4)

    def test_false_positive_tracking(self):
        """False positives can be marked and tracked."""
        analytics = GuardrailAnalytics()

        @check(name="fp-check", action=Action.BLOCK)
        def fp_check(text: str) -> dict:
            return {"detected": True, "confidence": 0.8}

        p = pipeline(name="test", checks=[fp_check])
        analytics.record(p.run("text"))
        analytics.record(p.run("text"))

        analytics.mark_false_positive("fp-check", count=1)

        check_info = analytics.check_summary("fp-check")
        assert check_info["false_positives"] == 1
        assert check_info["false_positive_rate"] == 0.5

    def test_latency_percentiles(self):
        """Latency percentiles are calculated."""
        analytics = GuardrailAnalytics()

        @check(name="fast", action=Action.BLOCK)
        def fast_check(text: str) -> dict:
            return {"detected": False, "confidence": 0.0}

        p = pipeline(name="test", checks=[fast_check])

        for _ in range(20):
            analytics.record(p.run("text"))

        summary = analytics.summary()
        assert summary["p50_latency_ms"] >= 0
        assert summary["p95_latency_ms"] >= summary["p50_latency_ms"]
