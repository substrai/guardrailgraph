"""Built-in prompt injection detection check.

Detects attempts to manipulate LLM behavior through:
1. Instruction override patterns ("ignore previous instructions")
2. Role-play manipulation ("you are now DAN")
3. Encoding tricks (base64, rot13, unicode)
4. Delimiter injection (closing/opening system prompts)
5. Context manipulation
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional

from guardrailgraph.core.actions import Action
from guardrailgraph.core.check import Check, check
from guardrailgraph.core.context import CheckContext


# Injection detection patterns with severity scores
INJECTION_PATTERNS: List[Dict[str, Any]] = [
    # Instruction override
    {
        "name": "instruction_override",
        "patterns": [
            r"ignore\s+(all\s+)?(previous|prior|above)\s+(instructions?|prompts?|rules?)",
            r"disregard\s+(all\s+)?(previous|prior|above)",
            r"forget\s+(everything|all|your)\s+(instructions?|rules?|training)",
            r"override\s+(your|the|all)\s+(instructions?|rules?|constraints?)",
            r"new\s+instructions?\s*:",
        ],
        "severity": 0.95,
        "category": "override",
    },
    # Role manipulation
    {
        "name": "role_manipulation",
        "patterns": [
            r"you\s+are\s+now\s+(?:a\s+)?(?:DAN|evil|unrestricted|jailbroken)",
            r"pretend\s+(?:you\s+are|to\s+be)\s+(?:a\s+)?(?:different|evil|unrestricted)",
            r"act\s+as\s+(?:if|though)\s+you\s+(?:have\s+)?no\s+(?:rules|restrictions|limits)",
            r"enter\s+(?:DAN|developer|admin|god)\s+mode",
            r"switch\s+to\s+(?:unrestricted|unfiltered)\s+mode",
        ],
        "severity": 0.9,
        "category": "role_play",
    },
    # System prompt extraction
    {
        "name": "system_prompt_extraction",
        "patterns": [
            r"(?:show|reveal|display|print|output)\s+(?:me\s+)?(?:your|the)\s+(?:system\s+)?(?:prompt|instructions)",
            r"what\s+(?:are|is)\s+your\s+(?:system\s+)?(?:prompt|instructions|rules)",
            r"repeat\s+(?:your|the)\s+(?:system\s+)?(?:prompt|instructions)\s+(?:back|verbatim)",
        ],
        "severity": 0.8,
        "category": "extraction",
    },
    # Delimiter injection
    {
        "name": "delimiter_injection",
        "patterns": [
            r"</?system>",
            r"\[/?INST\]",
            r"```\s*system",
            r"<\|(?:im_start|im_end|system|endoftext)\|>",
            r"###\s*(?:System|Human|Assistant)\s*:",
        ],
        "severity": 0.85,
        "category": "delimiter",
    },
    # Encoding tricks
    {
        "name": "encoding_tricks",
        "patterns": [
            r"(?:decode|translate)\s+(?:this\s+)?(?:from\s+)?(?:base64|rot13|hex|binary)",
            r"(?:in|using)\s+(?:base64|rot13|hex|binary)\s*:",
            r"(?:aWdub3Jl|SWdub3Jl)",  # Common base64 for "ignore"
        ],
        "severity": 0.75,
        "category": "encoding",
    },
]


class InjectionDetector:
    """Configurable prompt injection detection engine.

    Args:
        detection_methods: Methods to use ("heuristic", "classifier").
        sensitivity: Detection sensitivity (low/medium/high).
        custom_patterns: Additional regex patterns to check.
    """

    def __init__(
        self,
        detection_methods: Optional[List[str]] = None,
        sensitivity: str = "high",
        custom_patterns: Optional[List[Dict[str, Any]]] = None,
    ):
        self.detection_methods = detection_methods or ["heuristic"]
        self.sensitivity = sensitivity
        self.patterns = INJECTION_PATTERNS.copy()

        if custom_patterns:
            self.patterns.extend(custom_patterns)

        # Adjust threshold based on sensitivity
        self._threshold_map = {
            "low": 0.9,
            "medium": 0.75,
            "high": 0.6,
        }

    def detect(self, text: str) -> Dict[str, Any]:
        """Detect prompt injection attempts in text.

        Returns:
            Dict with detection result, matched patterns, and severity.
        """
        matches: List[Dict[str, Any]] = []
        max_severity = 0.0

        for pattern_group in self.patterns:
            for pattern in pattern_group["patterns"]:
                if re.search(pattern, text, re.IGNORECASE):
                    matches.append({
                        "name": pattern_group["name"],
                        "category": pattern_group["category"],
                        "severity": pattern_group["severity"],
                        "pattern": pattern,
                    })
                    max_severity = max(max_severity, pattern_group["severity"])
                    break  # One match per group is enough

        threshold = self._threshold_map.get(self.sensitivity, 0.75)
        detected = max_severity >= threshold

        return {
            "detected": detected,
            "confidence": max_severity,
            "matches": matches,
            "match_count": len(matches),
            "categories": list(set(m["category"] for m in matches)),
        }

    def to_check(
        self,
        name: str = "prompt-injection",
        action: Action = Action.BLOCK,
        threshold: float = 0.6,
    ) -> Check:
        """Convert this detector into a Check instance."""
        detector = self

        @check(name=name, action=action, threshold=threshold)
        def _injection_check(text: str) -> dict:
            return detector.detect(text)

        return _injection_check


def injection_check(
    detection_methods: Optional[List[str]] = None,
    sensitivity: str = "high",
    action: Action = Action.BLOCK,
    threshold: float = 0.6,
    name: str = "prompt-injection",
) -> Check:
    """Create a prompt injection detection check.

    Args:
        detection_methods: Detection methods to use.
        sensitivity: Detection sensitivity (low/medium/high).
        action: Action when injection detected.
        threshold: Confidence threshold.
        name: Check name.

    Returns:
        Configured Check instance.

    Example:
        from guardrailgraph.checks import injection_check

        my_injection = injection_check(sensitivity="high")
    """
    detector = InjectionDetector(
        detection_methods=detection_methods,
        sensitivity=sensitivity,
    )
    return detector.to_check(name=name, action=action, threshold=threshold)
