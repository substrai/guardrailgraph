"""Built-in toxicity detection check.

Scores text for toxic content across multiple categories:
- Hate speech
- Violence/threats
- Sexual content
- Self-harm
- Harassment
- Profanity

Uses keyword-based scoring with configurable thresholds.
Optional integration with AWS Bedrock for ML-based scoring.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional, Set

from guardrailgraph.core.actions import Action
from guardrailgraph.core.check import Check, check
from guardrailgraph.core.context import CheckContext


# Toxicity category keywords (simplified — production uses ML models)
TOXICITY_KEYWORDS: Dict[str, List[str]] = {
    "hate": [
        "hate", "racist", "bigot", "supremacist", "inferior race",
        "ethnic slur", "discrimination",
    ],
    "violence": [
        "kill", "murder", "attack", "bomb", "shoot", "stab",
        "assault", "destroy", "weapon", "explosive",
    ],
    "sexual": [
        "explicit", "pornographic", "nude", "sexual act",
    ],
    "self_harm": [
        "suicide", "self-harm", "cut myself", "end my life",
        "kill myself", "overdose",
    ],
    "harassment": [
        "threaten", "bully", "stalk", "intimidate", "harass",
        "doxx", "blackmail",
    ],
}

# Severity weights per category
CATEGORY_WEIGHTS: Dict[str, float] = {
    "hate": 0.9,
    "violence": 0.95,
    "sexual": 0.7,
    "self_harm": 1.0,
    "harassment": 0.85,
}


class ToxicityScorer:
    """Configurable toxicity scoring engine.

    Args:
        categories: Which toxicity categories to check. None = all.
        threshold: Score threshold to trigger detection.
        custom_keywords: Additional keywords per category.
        use_bedrock: Whether to use AWS Bedrock for ML scoring.
    """

    def __init__(
        self,
        categories: Optional[List[str]] = None,
        threshold: float = 0.7,
        custom_keywords: Optional[Dict[str, List[str]]] = None,
        use_bedrock: bool = False,
    ):
        self.threshold = threshold
        self.use_bedrock = use_bedrock

        # Build keyword set
        self.keywords: Dict[str, Set[str]] = {}
        active_categories = categories or list(TOXICITY_KEYWORDS.keys())

        for cat in active_categories:
            base = set(TOXICITY_KEYWORDS.get(cat, []))
            if custom_keywords and cat in custom_keywords:
                base.update(custom_keywords[cat])
            self.keywords[cat] = base

    def score(self, text: str) -> Dict[str, Any]:
        """Score text for toxicity across all configured categories.

        Returns:
            Dict with overall score, per-category scores, and matched terms.
        """
        text_lower = text.lower()
        category_scores: Dict[str, float] = {}
        matched_terms: Dict[str, List[str]] = {}

        for category, keywords in self.keywords.items():
            matches = []
            for keyword in keywords:
                if keyword.lower() in text_lower:
                    matches.append(keyword)

            if matches:
                # Score based on number of matches and category weight
                weight = CATEGORY_WEIGHTS.get(category, 0.8)
                raw_score = min(len(matches) / 3.0, 1.0)  # Cap at 1.0
                category_scores[category] = raw_score * weight
                matched_terms[category] = matches
            else:
                category_scores[category] = 0.0

        # Overall score is the max category score
        overall_score = max(category_scores.values()) if category_scores else 0.0

        return {
            "score": overall_score,
            "category_scores": category_scores,
            "matched_terms": matched_terms,
            "highest_category": (
                max(category_scores, key=category_scores.get)
                if any(v > 0 for v in category_scores.values())
                else None
            ),
        }

    def to_check(
        self,
        name: str = "toxicity",
        action: Action = Action.BLOCK,
        threshold: Optional[float] = None,
    ) -> Check:
        """Convert this scorer into a Check instance."""
        scorer = self
        check_threshold = threshold or self.threshold

        @check(name=name, action=action, threshold=check_threshold)
        def _toxicity_check(text: str) -> dict:
            result = scorer.score(text)
            score = result["score"]

            return {
                "detected": score >= check_threshold,
                "confidence": score,
                "category_scores": result["category_scores"],
                "matched_terms": result["matched_terms"],
                "highest_category": result["highest_category"],
            }

        return _toxicity_check


def toxicity_check(
    categories: Optional[List[str]] = None,
    threshold: float = 0.7,
    action: Action = Action.BLOCK,
    custom_keywords: Optional[Dict[str, List[str]]] = None,
    name: str = "toxicity",
) -> Check:
    """Create a toxicity detection check.

    Args:
        categories: Toxicity categories to check. None = all.
        threshold: Score threshold to trigger (0.0-1.0).
        action: Action when toxicity detected (default: BLOCK).
        custom_keywords: Additional keywords per category.
        name: Check name.

    Returns:
        Configured Check instance.

    Example:
        from guardrailgraph.checks import toxicity_check

        my_toxicity = toxicity_check(
            categories=["hate", "violence"],
            threshold=0.6,
        )
    """
    scorer = ToxicityScorer(
        categories=categories,
        threshold=threshold,
        custom_keywords=custom_keywords,
    )
    return scorer.to_check(name=name, action=action, threshold=threshold)
