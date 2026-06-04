"""Hallucination detection check using source grounding.

Cross-references LLM responses against provided source documents to detect
unsupported claims and fabricated information.

Detection methods:
1. Source grounding — check if claims are supported by provided sources
2. Factual consistency — detect contradictions within the response
3. Confidence calibration — flag overly confident unsupported claims
4. Evidence extraction — identify supporting passages from sources

Features:
- Sentence-level grounding scores
- Configurable threshold for hallucination detection
- Evidence extraction linking claims to source passages
- Support for multiple source documents with attribution
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple

from guardrailgraph.core.actions import Action
from guardrailgraph.core.check import Check, check
from guardrailgraph.core.context import CheckContext


# Indicators of potentially hallucinated content
HALLUCINATION_INDICATORS = [
    # Overly specific fabricated details
    r"(?:founded|established|created)\s+(?:in|on)\s+(?:January|February|March|April|May|June|July|August|September|October|November|December)\s+\d{1,2},?\s+\d{4}",
    # Fake citations
    r"according\s+to\s+(?:a\s+)?(?:\d{4}\s+)?study\s+(?:by|from|in)\s+",
    r"research\s+(?:published|conducted)\s+(?:by|in|at)\s+",
    # Confident claims without hedging
    r"(?:it\s+is\s+)?(?:a\s+)?(?:well-known|established|proven|scientific)\s+fact\s+that",
    r"studies\s+(?:have\s+)?(?:conclusively|definitively|clearly)\s+(?:shown|proven|demonstrated)",
]

# Hedging language (indicates the model is uncertain — good sign)
HEDGING_PHRASES = [
    "i'm not sure", "i don't know", "i cannot confirm",
    "it's possible that", "this may not be accurate",
    "i don't have information", "please verify",
    "i cannot guarantee", "to the best of my knowledge",
    "i'm unable to confirm", "this is approximate",
]

# Contradiction patterns
CONTRADICTION_PAIRS = [
    (r"\bis\b", r"\bis\s+not\b"),
    (r"\bwas\b", r"\bwas\s+not\b"),
    (r"\balways\b", r"\bnever\b"),
    (r"\beveryone\b", r"\bno\s+one\b"),
    (r"\ball\b", r"\bnone\b"),
]

# Stop words excluded from grounding analysis
STOP_WORDS = frozenset({
    "the", "a", "an", "is", "are", "was", "were", "in", "on", "at",
    "to", "for", "of", "and", "or", "but", "it", "its", "this", "that",
    "be", "been", "being", "have", "has", "had", "do", "does", "did",
    "will", "would", "could", "should", "may", "might", "shall", "can",
    "with", "from", "by", "as", "if", "then", "than", "so", "no", "not",
})


@dataclass
class SentenceGrounding:
    """Grounding result for a single sentence.

    Attributes:
        sentence: The original sentence from the LLM response.
        score: Grounding score between 0.0 (hallucinated) and 1.0 (grounded).
        is_grounded: Whether the sentence meets the threshold.
        evidence: Supporting passages from source documents.
        source_index: Index of the best-matching source document.
    """

    sentence: str
    score: float
    is_grounded: bool
    evidence: List[str] = field(default_factory=list)
    source_index: Optional[int] = None


@dataclass
class GroundingResult:
    """Complete grounding analysis result.

    Attributes:
        overall_score: Average grounding score across all sentences.
        sentence_scores: Per-sentence grounding details.
        unsupported_claims: Sentences that failed grounding.
        supported_claims: Sentences that passed grounding.
        evidence_map: Mapping of claims to supporting evidence passages.
        hallucination_detected: Whether overall score is below threshold.
    """

    overall_score: float
    sentence_scores: List[SentenceGrounding]
    unsupported_claims: List[str]
    supported_claims: List[str]
    evidence_map: Dict[str, List[str]]
    hallucination_detected: bool


class SourceGroundingChecker:
    """Sentence-level source grounding checker.

    Compares each sentence in the LLM output against provided source
    documents and computes grounding scores with evidence extraction.

    Args:
        threshold: Minimum grounding score to consider a sentence grounded.
        min_sentence_length: Minimum character length for a sentence to analyze.
        ngram_size: N-gram size for overlap computation.
        evidence_window: Number of words around a match to extract as evidence.
    """

    def __init__(
        self,
        threshold: float = 0.5,
        min_sentence_length: int = 20,
        ngram_size: int = 3,
        evidence_window: int = 30,
    ):
        self.threshold = threshold
        self.min_sentence_length = min_sentence_length
        self.ngram_size = ngram_size
        self.evidence_window = evidence_window

    def extract_sentences(self, text: str) -> List[str]:
        """Split text into sentences for analysis.

        Args:
            text: The text to split.

        Returns:
            List of sentence strings.
        """
        sentences = re.split(r'(?<=[.!?])\s+', text.strip())
        return [
            s.strip() for s in sentences
            if len(s.strip()) >= self.min_sentence_length
        ]

    def compute_ngrams(self, words: List[str], n: int) -> set:
        """Compute n-grams from a list of words.

        Args:
            words: List of words.
            n: N-gram size.

        Returns:
            Set of n-gram tuples.
        """
        if len(words) < n:
            return {tuple(words)} if words else set()
        return {tuple(words[i:i + n]) for i in range(len(words) - n + 1)}

    def extract_content_words(self, text: str) -> List[str]:
        """Extract meaningful content words from text.

        Args:
            text: Input text.

        Returns:
            List of lowercased content words.
        """
        words = re.findall(r'\b[a-zA-Z]+\b', text.lower())
        return [w for w in words if w not in STOP_WORDS and len(w) > 2]

    def find_evidence(
        self, sentence: str, source: str
    ) -> Tuple[float, List[str]]:
        """Find evidence in a source document for a given sentence.

        Computes overlap score and extracts supporting passages.

        Args:
            sentence: The claim sentence to ground.
            source: The source document text.

        Returns:
            Tuple of (score, list of evidence passages).
        """
        sent_words = self.extract_content_words(sentence)
        if not sent_words:
            return 0.0, []

        source_words = self.extract_content_words(source)
        if not source_words:
            return 0.0, []

        # Word overlap score
        sent_set = set(sent_words)
        source_set = set(source_words)
        word_overlap = len(sent_set & source_set) / len(sent_set) if sent_set else 0

        # N-gram overlap for phrase-level matching
        sent_ngrams = self.compute_ngrams(sent_words, self.ngram_size)
        source_ngrams = self.compute_ngrams(source_words, self.ngram_size)

        ngram_overlap = 0.0
        if sent_ngrams:
            ngram_overlap = len(sent_ngrams & source_ngrams) / len(sent_ngrams)

        # Combined score (weighted: ngrams matter more for grounding)
        score = 0.4 * word_overlap + 0.6 * ngram_overlap

        # Extract evidence passages
        evidence = []
        if score > 0:
            source_lower = source.lower()
            # Find the best matching window in the source
            for word in sent_words[:5]:  # Check key words
                idx = source_lower.find(word)
                if idx >= 0:
                    # Extract surrounding context
                    start = max(0, idx - 50)
                    end = min(len(source), idx + 100)
                    passage = source[start:end].strip()
                    if passage and passage not in evidence:
                        evidence.append(f"...{passage}...")
                        if len(evidence) >= 3:
                            break

        return score, evidence

    def check_grounding(
        self, text: str, sources: List[str]
    ) -> GroundingResult:
        """Check grounding of all sentences against source documents.

        Args:
            text: The LLM response to check.
            sources: List of source documents.

        Returns:
            GroundingResult with per-sentence scores and evidence.
        """
        sentences = self.extract_sentences(text)

        if not sentences:
            return GroundingResult(
                overall_score=1.0,
                sentence_scores=[],
                unsupported_claims=[],
                supported_claims=[],
                evidence_map={},
                hallucination_detected=False,
            )

        sentence_scores: List[SentenceGrounding] = []
        unsupported: List[str] = []
        supported: List[str] = []
        evidence_map: Dict[str, List[str]] = {}

        for sentence in sentences:
            best_score = 0.0
            best_evidence: List[str] = []
            best_source_idx: Optional[int] = None

            for idx, source in enumerate(sources):
                score, evidence = self.find_evidence(sentence, source)
                if score > best_score:
                    best_score = score
                    best_evidence = evidence
                    best_source_idx = idx

            is_grounded = best_score >= self.threshold

            sg = SentenceGrounding(
                sentence=sentence,
                score=best_score,
                is_grounded=is_grounded,
                evidence=best_evidence,
                source_index=best_source_idx,
            )
            sentence_scores.append(sg)

            if is_grounded:
                supported.append(sentence)
            else:
                unsupported.append(sentence)

            if best_evidence:
                evidence_map[sentence] = best_evidence

        overall_score = (
            sum(sg.score for sg in sentence_scores) / len(sentence_scores)
            if sentence_scores
            else 1.0
        )

        return GroundingResult(
            overall_score=overall_score,
            sentence_scores=sentence_scores,
            unsupported_claims=unsupported,
            supported_claims=supported,
            evidence_map=evidence_map,
            hallucination_detected=overall_score < self.threshold,
        )


class HallucinationDetector:
    """Configurable hallucination detection engine.

    Combines indicator-based detection with source grounding for
    comprehensive hallucination identification.

    Args:
        method: Detection method — "indicators", "grounding", or "hybrid".
        threshold: Confidence threshold for detection.
        knowledge_base: Optional list of approved source texts.
        max_claim_length: Maximum sentence length to analyze.
        grounding_threshold: Threshold for sentence-level grounding.
        ngram_size: N-gram size for grounding computation.
    """

    def __init__(
        self,
        method: str = "indicators",
        threshold: float = 0.6,
        knowledge_base: Optional[List[str]] = None,
        max_claim_length: int = 500,
        grounding_threshold: float = 0.5,
        ngram_size: int = 3,
    ):
        self.method = method
        self.threshold = threshold
        self.knowledge_base = knowledge_base or []
        self.max_claim_length = max_claim_length
        self.grounding_checker = SourceGroundingChecker(
            threshold=grounding_threshold,
            ngram_size=ngram_size,
        )

    def detect(
        self, text: str, sources: Optional[List[str]] = None
    ) -> Dict[str, Any]:
        """Detect potential hallucinations in text.

        Args:
            text: The LLM response to check.
            sources: Optional source documents to ground against.

        Returns:
            Dict with detection result, grounding score, indicators,
            and evidence extraction results.
        """
        results: Dict[str, Any] = {
            "indicators_found": [],
            "hedging_present": False,
            "contradiction_detected": False,
            "grounding_score": 1.0,
            "grounding_result": None,
        }

        # Method 1: Check for hallucination indicators
        indicator_score = self._check_indicators(text, results)

        # Method 2: Check for hedging (good — means model is calibrated)
        hedging_score = self._check_hedging(text, results)

        # Method 3: Check for contradictions
        contradiction_score = self._check_contradictions(text, results)

        # Method 4: Source grounding (if sources provided)
        grounding_score = 1.0
        effective_sources = sources or self.knowledge_base
        if effective_sources and self.method in ("grounding", "hybrid"):
            grounding_result = self.grounding_checker.check_grounding(
                text, effective_sources
            )
            grounding_score = grounding_result.overall_score
            results["grounding_result"] = grounding_result
            results["grounding_score"] = grounding_score

        # Calculate overall hallucination risk
        if self.method == "grounding":
            risk_score = 1.0 - grounding_score
        elif self.method == "hybrid":
            risk_score = max(indicator_score, 1.0 - grounding_score)
        else:
            risk_score = indicator_score

        # Reduce risk if hedging is present (model is being honest)
        if results["hedging_present"]:
            risk_score *= 0.5

        # Increase risk if contradictions found
        if results["contradiction_detected"]:
            risk_score = min(risk_score + 0.3, 1.0)

        detected = risk_score >= self.threshold

        return {
            "detected": detected,
            "confidence": risk_score,
            "grounding_score": grounding_score,
            "indicators_found": results["indicators_found"],
            "hedging_present": results["hedging_present"],
            "contradiction_detected": results["contradiction_detected"],
            "grounding_result": results["grounding_result"],
            "method": self.method,
        }

    def _check_indicators(self, text: str, results: Dict) -> float:
        """Check for hallucination indicator patterns."""
        found = []
        for pattern in HALLUCINATION_INDICATORS:
            if re.search(pattern, text, re.IGNORECASE):
                found.append(pattern)

        results["indicators_found"] = found
        return min(len(found) / 3.0, 1.0)

    def _check_hedging(self, text: str, results: Dict) -> float:
        """Check for hedging language (indicates calibrated uncertainty)."""
        text_lower = text.lower()
        hedges = [h for h in HEDGING_PHRASES if h in text_lower]
        results["hedging_present"] = len(hedges) > 0
        return min(len(hedges) / 2.0, 1.0)

    def _check_contradictions(self, text: str, results: Dict) -> float:
        """Check for internal contradictions."""
        sentences = re.split(r'[.!?]+', text)
        contradiction_count = 0

        for i, sent1 in enumerate(sentences):
            for sent2 in sentences[i + 1:]:
                for pos_pattern, neg_pattern in CONTRADICTION_PAIRS:
                    if (re.search(pos_pattern, sent1, re.IGNORECASE) and
                            re.search(neg_pattern, sent2, re.IGNORECASE)):
                        words1 = set(sent1.lower().split())
                        words2 = set(sent2.lower().split())
                        overlap = words1 & words2
                        if len(overlap) >= 3:
                            contradiction_count += 1

        results["contradiction_detected"] = contradiction_count > 0
        return min(contradiction_count / 2.0, 1.0)

    def to_check(
        self,
        name: str = "hallucination",
        action: Action = Action.FLAG_FOR_REVIEW,
        threshold: Optional[float] = None,
    ) -> Check:
        """Convert this detector into a Check instance."""
        detector = self

        @check(name=name, action=action, threshold=threshold or self.threshold)
        def _hallucination_check(text: str, context: CheckContext) -> dict:
            sources = None
            if context and context.knowledge_base:
                sources = context.knowledge_base
            elif context and "sources" in context.config:
                sources = context.config["sources"]
            return detector.detect(text, sources)

        return _hallucination_check


def hallucination_check(
    method: str = "indicators",
    threshold: float = 0.6,
    knowledge_base: Optional[List[str]] = None,
    action: Action = Action.FLAG_FOR_REVIEW,
    name: str = "hallucination",
    grounding_threshold: float = 0.5,
) -> Check:
    """Create a hallucination detection check.

    Args:
        method: Detection method — "indicators", "grounding", or "hybrid".
        threshold: Confidence threshold to trigger.
        knowledge_base: Approved source texts for grounding.
        action: Action when hallucination detected.
        name: Check name.
        grounding_threshold: Sentence-level grounding threshold.

    Returns:
        Configured Check instance.

    Example:
        from guardrailgraph.checks import hallucination_check

        my_hallucination = hallucination_check(
            method="hybrid",
            knowledge_base=["Approved fact 1", "Approved fact 2"],
            grounding_threshold=0.4,
        )
    """
    detector = HallucinationDetector(
        method=method,
        threshold=threshold,
        knowledge_base=knowledge_base,
        grounding_threshold=grounding_threshold,
    )
    return detector.to_check(name=name, action=action, threshold=threshold)
