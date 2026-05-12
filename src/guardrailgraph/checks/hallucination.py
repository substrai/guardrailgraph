"""Built-in hallucination detection check.

Cross-references LLM responses against approved knowledge bases
to detect unsupported claims and fabricated information.

Detection methods:
1. Source grounding — check if claims are supported by provided sources
2. Factual consistency — detect contradictions within the response
3. Confidence calibration — flag overly confident unsupported claims
"""

from __future__ import annotations

import re
from typing import Any, Callable, Dict, List, Optional, Sequence

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


class HallucinationDetector:
    """Configurable hallucination detection engine.

    Args:
        method: Detection method — "indicators", "grounding", or "hybrid".
        threshold: Confidence threshold for detection.
        knowledge_base: Optional list of approved source texts.
        max_claim_length: Maximum sentence length to analyze.
    """

    def __init__(
        self,
        method: str = "indicators",
        threshold: float = 0.6,
        knowledge_base: Optional[List[str]] = None,
        max_claim_length: int = 500,
    ):
        self.method = method
        self.threshold = threshold
        self.knowledge_base = knowledge_base or []
        self.max_claim_length = max_claim_length

    def detect(self, text: str, sources: Optional[List[str]] = None) -> Dict[str, Any]:
        """Detect potential hallucinations in text.

        Args:
            text: The LLM response to check.
            sources: Optional source documents to ground against.

        Returns:
            Dict with detection result, grounding score, and indicators.
        """
        results: Dict[str, Any] = {
            "indicators_found": [],
            "hedging_present": False,
            "contradiction_detected": False,
            "grounding_score": 1.0,
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
            grounding_score = self._check_grounding(text, effective_sources, results)

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
                        # Check if they're about the same subject
                        words1 = set(sent1.lower().split())
                        words2 = set(sent2.lower().split())
                        overlap = words1 & words2
                        if len(overlap) >= 3:
                            contradiction_count += 1

        results["contradiction_detected"] = contradiction_count > 0
        return min(contradiction_count / 2.0, 1.0)

    def _check_grounding(
        self, text: str, sources: List[str], results: Dict
    ) -> float:
        """Check how well the text is grounded in source documents.

        Uses simple word overlap as a proxy for semantic grounding.
        Production systems would use embeddings.
        """
        if not sources:
            results["grounding_score"] = 0.5
            return 0.5

        # Extract key claims (sentences with factual assertions)
        sentences = [s.strip() for s in re.split(r'[.!?]+', text) if len(s.strip()) > 20]

        if not sentences:
            results["grounding_score"] = 1.0
            return 1.0

        # Check each sentence against sources
        source_text = " ".join(sources).lower()
        source_words = set(source_text.split())

        grounded_count = 0
        for sentence in sentences:
            sent_words = set(sentence.lower().split()) - {"the", "a", "an", "is", "are", "was", "were", "in", "on", "at", "to", "for"}
            if not sent_words:
                continue
            overlap = sent_words & source_words
            overlap_ratio = len(overlap) / len(sent_words)
            if overlap_ratio >= 0.4:
                grounded_count += 1

        grounding_score = grounded_count / max(len(sentences), 1)
        results["grounding_score"] = grounding_score
        return grounding_score

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
) -> Check:
    """Create a hallucination detection check.

    Args:
        method: Detection method — "indicators", "grounding", or "hybrid".
        threshold: Confidence threshold to trigger.
        knowledge_base: Approved source texts for grounding.
        action: Action when hallucination detected.
        name: Check name.

    Returns:
        Configured Check instance.

    Example:
        from guardrailgraph.checks import hallucination_check

        my_hallucination = hallucination_check(
            method="hybrid",
            knowledge_base=["Approved fact 1", "Approved fact 2"],
        )
    """
    detector = HallucinationDetector(
        method=method,
        threshold=threshold,
        knowledge_base=knowledge_base,
    )
    return detector.to_check(name=name, action=action, threshold=threshold)
