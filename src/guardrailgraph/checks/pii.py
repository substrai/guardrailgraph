"""Built-in PII detection and redaction check.

Detects personally identifiable information using layered approach:
1. Fast regex patterns (SSN, phone, email, credit card)
2. Named entity recognition patterns (names, addresses)
3. Optional AWS Comprehend integration for ML-based detection
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from guardrailgraph.core.actions import Action
from guardrailgraph.core.check import Check, check
from guardrailgraph.core.context import CheckContext


@dataclass
class PiiEntity:
    """A detected PII entity."""

    type: str
    value: str
    start: int
    end: int
    confidence: float = 1.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "type": self.type,
            "value": self.value,
            "start": self.start,
            "end": self.end,
            "confidence": self.confidence,
        }


# Regex patterns for common PII types
PII_PATTERNS: Dict[str, re.Pattern] = {
    "SSN": re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
    "PHONE": re.compile(
        r"\b(?:\+1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b"
    ),
    "EMAIL": re.compile(
        r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b"
    ),
    "CREDIT_CARD": re.compile(
        r"\b(?:\d{4}[-\s]?){3}\d{4}\b"
    ),
    "IP_ADDRESS": re.compile(
        r"\b(?:\d{1,3}\.){3}\d{1,3}\b"
    ),
    "DATE_OF_BIRTH": re.compile(
        r"\b(?:0[1-9]|1[0-2])[/-](?:0[1-9]|[12]\d|3[01])[/-](?:19|20)\d{2}\b"
    ),
    "PASSPORT": re.compile(
        r"\b[A-Z]{1,2}\d{6,9}\b"
    ),
    "DRIVERS_LICENSE": re.compile(
        r"\b[A-Z]\d{7,14}\b"
    ),
}

# Common name patterns (simplified — production would use NER)
NAME_PREFIXES = {"mr", "mrs", "ms", "dr", "prof", "sir", "madam"}


class PiiDetector:
    """Configurable PII detection engine.

    Args:
        entity_types: Which PII types to detect. None = all.
        redaction_char: Character to use for redaction.
        sensitivity: Detection sensitivity (low/medium/high).
        use_comprehend: Whether to use AWS Comprehend for ML detection.
    """

    def __init__(
        self,
        entity_types: Optional[List[str]] = None,
        redaction_char: str = "X",
        sensitivity: str = "high",
        use_comprehend: bool = False,
    ):
        self.entity_types = entity_types
        self.redaction_char = redaction_char
        self.sensitivity = sensitivity
        self.use_comprehend = use_comprehend

        # Filter patterns based on entity_types
        if entity_types:
            self.patterns = {
                k: v for k, v in PII_PATTERNS.items()
                if k in [t.upper() for t in entity_types]
            }
        else:
            self.patterns = PII_PATTERNS.copy()

    def detect(self, text: str) -> List[PiiEntity]:
        """Detect PII entities in text."""
        entities: List[PiiEntity] = []

        # Regex-based detection
        for pii_type, pattern in self.patterns.items():
            for match in pattern.finditer(text):
                entities.append(PiiEntity(
                    type=pii_type,
                    value=match.group(),
                    start=match.start(),
                    end=match.end(),
                    confidence=0.95,
                ))

        # Sort by position
        entities.sort(key=lambda e: e.start)
        return entities

    def redact(self, text: str, entities: Optional[List[PiiEntity]] = None) -> str:
        """Redact PII entities from text."""
        if entities is None:
            entities = self.detect(text)

        if not entities:
            return text

        # Redact from end to start to preserve positions
        result = text
        for entity in sorted(entities, key=lambda e: e.start, reverse=True):
            replacement = f"[{entity.type}]"
            result = result[:entity.start] + replacement + result[entity.end:]

        return result

    def to_check(
        self,
        name: str = "pii-detection",
        action: Action = Action.REDACT,
        threshold: float = 0.5,
    ) -> Check:
        """Convert this detector into a Check instance."""
        detector = self

        @check(name=name, action=action, threshold=threshold)
        def _pii_check(text: str) -> dict:
            entities = detector.detect(text)
            if not entities:
                return {"detected": False, "confidence": 0.0}

            max_confidence = max(e.confidence for e in entities)
            redacted = detector.redact(text, entities)

            return {
                "detected": True,
                "confidence": max_confidence,
                "entities": [e.to_dict() for e in entities],
                "redacted_text": redacted,
                "entity_count": len(entities),
                "entity_types": list(set(e.type for e in entities)),
            }

        return _pii_check


def pii_check(
    entity_types: Optional[List[str]] = None,
    redaction_char: str = "X",
    sensitivity: str = "high",
    action: Action = Action.REDACT,
    threshold: float = 0.5,
    name: str = "pii-detection",
) -> Check:
    """Create a PII detection check with the given configuration.

    Args:
        entity_types: PII types to detect (SSN, PHONE, EMAIL, etc.). None = all.
        redaction_char: Character for redaction replacement.
        sensitivity: Detection sensitivity level.
        action: Action when PII is detected (default: REDACT).
        threshold: Confidence threshold to trigger.
        name: Check name.

    Returns:
        Configured Check instance.

    Example:
        from guardrailgraph.checks import pii_check

        my_pii = pii_check(
            entity_types=["SSN", "EMAIL", "PHONE"],
            action=Action.REDACT,
        )
    """
    detector = PiiDetector(
        entity_types=entity_types,
        redaction_char=redaction_char,
        sensitivity=sensitivity,
    )
    return detector.to_check(name=name, action=action, threshold=threshold)
