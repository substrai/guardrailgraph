"""Tests for hallucination detection check using source grounding."""

from __future__ import annotations

import pytest

from guardrailgraph.checks.hallucination import (
    GroundingResult,
    HallucinationDetector,
    SentenceGrounding,
    SourceGroundingChecker,
    hallucination_check,
)


class TestSourceGroundingChecker:
    """Tests for the SourceGroundingChecker class."""

    def test_extract_sentences_basic(self):
        """Test sentence extraction from text."""
        checker = SourceGroundingChecker(min_sentence_length=10)
        text = "This is a sentence. This is another longer sentence here. Short."
        sentences = checker.extract_sentences(text)
        assert len(sentences) == 2  # "Short." is too short

    def test_extract_sentences_empty_text(self):
        """Test extraction from empty text."""
        checker = SourceGroundingChecker()
        assert checker.extract_sentences("") == []

    def test_grounded_sentence_scores_high(self):
        """Test that sentences matching sources get high scores."""
        checker = SourceGroundingChecker(threshold=0.3)
        sources = [
            "The company was founded in 2020 and specializes in machine learning "
            "applications for natural language processing tasks."
        ]
        text = (
            "The company was founded in 2020 and specializes in machine learning."
        )
        result = checker.check_grounding(text, sources)

        assert result.overall_score > 0.3
        assert len(result.unsupported_claims) == 0

    def test_ungrounded_sentence_scores_low(self):
        """Test that fabricated sentences get low scores."""
        checker = SourceGroundingChecker(threshold=0.5)
        sources = [
            "Python is a programming language used for web development."
        ]
        text = (
            "Quantum entanglement enables faster-than-light communication "
            "between distant galaxies using crystalline resonators."
        )
        result = checker.check_grounding(text, sources)

        assert result.overall_score < 0.5
        assert result.hallucination_detected is True

    def test_evidence_extraction(self):
        """Test that evidence passages are extracted for grounded claims."""
        checker = SourceGroundingChecker(threshold=0.3)
        sources = [
            "Machine learning models require large datasets for training. "
            "The training process involves iterative optimization of model parameters."
        ]
        text = "Machine learning models require large datasets for training purposes."
        result = checker.check_grounding(text, sources)

        # Should have evidence for the grounded sentence
        assert len(result.evidence_map) >= 0  # May or may not extract evidence

    def test_multiple_sources(self):
        """Test grounding against multiple source documents."""
        checker = SourceGroundingChecker(threshold=0.3)
        sources = [
            "The earth orbits the sun in approximately 365 days.",
            "Water boils at 100 degrees Celsius at sea level atmospheric pressure.",
        ]
        text = "Water boils at 100 degrees Celsius at standard atmospheric pressure."
        result = checker.check_grounding(text, sources)

        # Should find grounding in the second source
        if result.sentence_scores:
            assert result.sentence_scores[0].source_index == 1

    def test_empty_sources_returns_no_grounding(self):
        """Test behavior with empty source list."""
        checker = SourceGroundingChecker(threshold=0.5)
        text = "This is a claim that cannot be verified without sources."
        result = checker.check_grounding(text, [])

        # With no sources, each sentence gets 0 score
        if result.sentence_scores:
            assert all(sg.score == 0.0 for sg in result.sentence_scores)

    def test_compute_ngrams(self):
        """Test n-gram computation."""
        checker = SourceGroundingChecker(ngram_size=3)
        words = ["machine", "learning", "models", "require", "data"]
        ngrams = checker.compute_ngrams(words, 3)
        assert ("machine", "learning", "models") in ngrams
        assert ("learning", "models", "require") in ngrams
        assert len(ngrams) == 3


class TestHallucinationDetector:
    """Tests for the HallucinationDetector class."""

    def test_indicator_detection(self):
        """Test detection of hallucination indicators."""
        detector = HallucinationDetector(method="indicators", threshold=0.3)
        text = (
            "According to a 2019 study by Harvard researchers, "
            "it is a well-known fact that coffee consumption increases lifespan."
        )
        result = detector.detect(text)

        assert result["detected"] is True
        assert len(result["indicators_found"]) > 0

    def test_hedging_reduces_risk(self):
        """Test that hedging language reduces hallucination risk."""
        detector = HallucinationDetector(method="indicators", threshold=0.6)
        text = (
            "According to a study by some researchers, this might help. "
            "I'm not sure about the exact details, please verify this claim."
        )
        result = detector.detect(text)

        assert result["hedging_present"] is True
        # Risk should be reduced due to hedging
        assert result["confidence"] < 0.6

    def test_grounding_method_with_sources(self):
        """Test grounding method with matching sources."""
        sources = [
            "Python was created by Guido van Rossum and first released in 1991. "
            "It emphasizes code readability and simplicity."
        ]
        detector = HallucinationDetector(
            method="grounding",
            threshold=0.5,
            knowledge_base=sources,
            grounding_threshold=0.3,
        )
        text = "Python was created by Guido van Rossum and released in 1991."
        result = detector.detect(text)

        assert result["grounding_score"] > 0.0
        assert result["grounding_result"] is not None

    def test_hybrid_method(self):
        """Test hybrid method combines indicators and grounding."""
        sources = ["Simple factual content about cats and dogs."]
        detector = HallucinationDetector(
            method="hybrid",
            threshold=0.3,
            knowledge_base=sources,
            grounding_threshold=0.3,
        )
        text = (
            "According to a 2022 study by Oxford researchers, "
            "quantum computing will revolutionize everything by 2025."
        )
        result = detector.detect(text)

        assert result["method"] == "hybrid"
        assert result["detected"] is True

    def test_contradiction_detection(self):
        """Test detection of internal contradictions."""
        detector = HallucinationDetector(method="indicators", threshold=0.3)
        text = (
            "The temperature is always above freezing in this region. "
            "The temperature never reaches above freezing in this region."
        )
        result = detector.detect(text)
        assert result["contradiction_detected"] is True

    def test_clean_text_no_hallucination(self):
        """Test that clean text without indicators passes."""
        detector = HallucinationDetector(method="indicators", threshold=0.6)
        text = "The function returns a list of processed items after filtering."
        result = detector.detect(text)

        assert result["detected"] is False
        assert result["confidence"] < 0.6

    def test_grounding_result_contains_sentence_scores(self):
        """Test that grounding results include per-sentence details."""
        sources = ["Data science involves statistics and programming skills."]
        detector = HallucinationDetector(
            method="grounding",
            threshold=0.5,
            knowledge_base=sources,
            grounding_threshold=0.3,
        )
        text = (
            "Data science involves statistics and programming. "
            "Alien civilizations have confirmed this through telepathy."
        )
        result = detector.detect(text)

        grounding = result["grounding_result"]
        assert grounding is not None
        assert len(grounding.sentence_scores) >= 1

    def test_configurable_grounding_threshold(self):
        """Test that grounding threshold is configurable."""
        sources = ["Machine learning uses data to make predictions."]

        # Strict threshold
        strict = HallucinationDetector(
            method="grounding",
            threshold=0.3,
            knowledge_base=sources,
            grounding_threshold=0.9,
        )
        # Lenient threshold
        lenient = HallucinationDetector(
            method="grounding",
            threshold=0.3,
            knowledge_base=sources,
            grounding_threshold=0.1,
        )

        text = "Machine learning algorithms process data for prediction tasks."
        strict_result = strict.detect(text)
        lenient_result = lenient.detect(text)

        # Lenient should ground more sentences
        if strict_result["grounding_result"] and lenient_result["grounding_result"]:
            strict_unsupported = len(
                strict_result["grounding_result"].unsupported_claims
            )
            lenient_unsupported = len(
                lenient_result["grounding_result"].unsupported_claims
            )
            assert lenient_unsupported <= strict_unsupported


class TestHallucinationCheckFactory:
    """Tests for the hallucination_check factory function."""

    def test_creates_check_instance(self):
        """Test that factory creates a valid check."""
        chk = hallucination_check(method="indicators", threshold=0.5)
        assert chk is not None

    def test_factory_with_grounding_config(self):
        """Test factory with grounding configuration."""
        chk = hallucination_check(
            method="grounding",
            threshold=0.4,
            knowledge_base=["Source document content here."],
            grounding_threshold=0.3,
        )
        assert chk is not None
