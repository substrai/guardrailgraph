"""Built-in semantic similarity check.

Detects responses that are too similar to known copyrighted content,
training data, or other protected material.

Uses character n-gram overlap as a lightweight similarity measure.
Production systems would use embedding-based similarity.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Set

from guardrailgraph.core.actions import Action
from guardrailgraph.core.check import Check, check
from guardrailgraph.core.context import CheckContext


def _ngrams(text: str, n: int = 3) -> Set[str]:
    """Generate character n-grams from text."""
    text = text.lower().strip()
    return {text[i:i + n] for i in range(len(text) - n + 1)}


def _jaccard_similarity(set1: Set[str], set2: Set[str]) -> float:
    """Calculate Jaccard similarity between two sets."""
    if not set1 or not set2:
        return 0.0
    intersection = len(set1 & set2)
    union = len(set1 | set2)
    return intersection / union if union > 0 else 0.0


class SemanticSimilarityDetector:
    """Detects text that is too similar to protected content.

    Args:
        protected_texts: List of protected/copyrighted texts.
        similarity_threshold: Minimum similarity to trigger (0.0-1.0).
        ngram_size: Size of character n-grams for comparison.
        min_text_length: Minimum text length to check (short texts ignored).
    """

    def __init__(
        self,
        protected_texts: Optional[List[str]] = None,
        similarity_threshold: float = 0.7,
        ngram_size: int = 4,
        min_text_length: int = 50,
    ):
        self.protected_texts = protected_texts or []
        self.similarity_threshold = similarity_threshold
        self.ngram_size = ngram_size
        self.min_text_length = min_text_length

        # Pre-compute n-grams for protected texts
        self._protected_ngrams = [
            _ngrams(text, ngram_size) for text in self.protected_texts
        ]

    def add_protected_text(self, text: str) -> None:
        """Add a protected text to check against."""
        self.protected_texts.append(text)
        self._protected_ngrams.append(_ngrams(text, self.ngram_size))

    def detect(self, text: str) -> Dict[str, Any]:
        """Check if text is too similar to any protected content.

        Returns:
            Dict with detection result, max similarity, and matched index.
        """
        if len(text) < self.min_text_length:
            return {"detected": False, "confidence": 0.0, "reason": "text_too_short"}

        if not self._protected_ngrams:
            return {"detected": False, "confidence": 0.0, "reason": "no_protected_texts"}

        text_ngrams = _ngrams(text, self.ngram_size)
        max_similarity = 0.0
        most_similar_idx = -1

        for i, protected_ng in enumerate(self._protected_ngrams):
            similarity = _jaccard_similarity(text_ngrams, protected_ng)
            if similarity > max_similarity:
                max_similarity = similarity
                most_similar_idx = i

        detected = max_similarity >= self.similarity_threshold

        return {
            "detected": detected,
            "confidence": max_similarity,
            "max_similarity": max_similarity,
            "most_similar_index": most_similar_idx if detected else None,
            "threshold": self.similarity_threshold,
        }

    def to_check(
        self,
        name: str = "semantic-similarity",
        action: Action = Action.BLOCK,
        threshold: Optional[float] = None,
    ) -> Check:
        """Convert this detector into a Check instance."""
        detector = self

        @check(name=name, action=action, threshold=threshold or self.similarity_threshold)
        def _semantic_check(text: str) -> dict:
            return detector.detect(text)

        return _semantic_check


def semantic_similarity_check(
    protected_texts: Optional[List[str]] = None,
    similarity_threshold: float = 0.7,
    action: Action = Action.BLOCK,
    name: str = "semantic-similarity",
) -> Check:
    """Create a semantic similarity check.

    Args:
        protected_texts: Texts to check against (copyrighted, training data).
        similarity_threshold: Similarity threshold to trigger (0.0-1.0).
        action: Action when similarity detected.
        name: Check name.

    Returns:
        Configured Check instance.

    Example:
        from guardrailgraph.checks import semantic_similarity_check

        copyright_check = semantic_similarity_check(
            protected_texts=["Original copyrighted content here..."],
            similarity_threshold=0.8,
        )
    """
    detector = SemanticSimilarityDetector(
        protected_texts=protected_texts,
        similarity_threshold=similarity_threshold,
    )
    return detector.to_check(name=name, action=action, threshold=similarity_threshold)
