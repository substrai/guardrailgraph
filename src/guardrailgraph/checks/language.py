"""Built-in multi-language support check.

Detects the language of input text and applies language-specific
guardrail rules. Supports detection and filtering across multiple languages.

Uses character frequency analysis and common word detection
for lightweight language identification without external dependencies.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional, Set

from guardrailgraph.core.actions import Action
from guardrailgraph.core.check import Check, check
from guardrailgraph.core.context import CheckContext


# Common words per language for detection
LANGUAGE_MARKERS: Dict[str, Set[str]] = {
    "en": {"the", "is", "are", "was", "were", "have", "has", "been", "will", "would", "could", "should", "this", "that", "with", "from", "they", "their"},
    "es": {"el", "la", "los", "las", "es", "son", "fue", "ser", "estar", "tiene", "para", "por", "como", "pero", "más", "este", "esta", "uno"},
    "fr": {"le", "la", "les", "est", "sont", "être", "avoir", "fait", "pour", "dans", "avec", "sur", "pas", "plus", "tout", "cette", "mais", "qui"},
    "de": {"der", "die", "das", "ist", "sind", "ein", "eine", "für", "mit", "auf", "nicht", "sich", "auch", "noch", "wie", "aber", "oder", "wenn"},
    "pt": {"o", "a", "os", "as", "é", "são", "foi", "ser", "estar", "tem", "para", "por", "como", "mas", "mais", "este", "esta", "uma"},
    "it": {"il", "la", "le", "è", "sono", "essere", "avere", "per", "con", "che", "non", "una", "questo", "questa", "anche", "più", "come", "ma"},
    "zh": set(),  # Detected by character range
    "ja": set(),  # Detected by character range
    "ko": set(),  # Detected by character range
    "ar": set(),  # Detected by character range
    "hi": set(),  # Detected by character range
}

# Unicode ranges for script detection
SCRIPT_RANGES = {
    "zh": (0x4E00, 0x9FFF),   # CJK Unified Ideographs
    "ja": (0x3040, 0x30FF),   # Hiragana + Katakana
    "ko": (0xAC00, 0xD7AF),   # Hangul Syllables
    "ar": (0x0600, 0x06FF),   # Arabic
    "hi": (0x0900, 0x097F),   # Devanagari
    "ru": (0x0400, 0x04FF),   # Cyrillic
}


class LanguageDetector:
    """Lightweight language detection engine.

    Args:
        allowed_languages: Languages to allow. None = all.
        blocked_languages: Languages to block.
        mode: "allowlist" or "blocklist".
    """

    def __init__(
        self,
        allowed_languages: Optional[List[str]] = None,
        blocked_languages: Optional[List[str]] = None,
        mode: str = "allowlist",
    ):
        self.allowed_languages = set(allowed_languages) if allowed_languages else None
        self.blocked_languages = set(blocked_languages) if blocked_languages else set()
        self.mode = mode

    def detect_language(self, text: str) -> Dict[str, float]:
        """Detect language(s) present in text.

        Returns:
            Dict mapping language codes to confidence scores.
        """
        scores: Dict[str, float] = {}

        # Check script-based languages first
        for lang, (start, end) in SCRIPT_RANGES.items():
            char_count = sum(1 for c in text if start <= ord(c) <= end)
            if char_count > 0:
                scores[lang] = min(char_count / max(len(text) * 0.3, 1), 1.0)

        # Check word-based languages
        words = set(re.findall(r'\b\w+\b', text.lower()))
        if words:
            for lang, markers in LANGUAGE_MARKERS.items():
                if not markers:
                    continue
                overlap = words & markers
                if overlap:
                    score = len(overlap) / min(len(words), 20)
                    scores[lang] = min(score * 2, 1.0)  # Boost small texts

        return scores

    def evaluate(self, text: str) -> Dict[str, Any]:
        """Evaluate text against language restrictions.

        Returns:
            Dict with detection result and language analysis.
        """
        detected_languages = self.detect_language(text)

        if not detected_languages:
            # Default to English if no language detected
            detected_languages = {"en": 0.5}

        primary_language = max(detected_languages, key=detected_languages.get)
        primary_confidence = detected_languages[primary_language]

        # Check against restrictions
        if self.mode == "allowlist" and self.allowed_languages:
            is_allowed = primary_language in self.allowed_languages
            return {
                "detected": not is_allowed,
                "confidence": primary_confidence if not is_allowed else 0.0,
                "detected_language": primary_language,
                "all_languages": detected_languages,
                "allowed": is_allowed,
                "reason": f"Language '{primary_language}' not in allowed list" if not is_allowed else None,
            }
        elif self.mode == "blocklist" and self.blocked_languages:
            is_blocked = primary_language in self.blocked_languages
            return {
                "detected": is_blocked,
                "confidence": primary_confidence if is_blocked else 0.0,
                "detected_language": primary_language,
                "all_languages": detected_languages,
                "blocked": is_blocked,
                "reason": f"Language '{primary_language}' is blocked" if is_blocked else None,
            }

        return {
            "detected": False,
            "confidence": 0.0,
            "detected_language": primary_language,
            "all_languages": detected_languages,
        }

    def to_check(
        self,
        name: str = "language-check",
        action: Action = Action.BLOCK,
        threshold: float = 0.5,
    ) -> Check:
        """Convert this detector into a Check instance."""
        detector = self

        @check(name=name, action=action, threshold=threshold)
        def _language_check(text: str) -> dict:
            return detector.evaluate(text)

        return _language_check


def language_check(
    allowed_languages: Optional[List[str]] = None,
    blocked_languages: Optional[List[str]] = None,
    mode: str = "allowlist",
    action: Action = Action.BLOCK,
    threshold: float = 0.5,
    name: str = "language-check",
) -> Check:
    """Create a language detection/restriction check.

    Args:
        allowed_languages: Language codes to allow (e.g., ["en", "es"]).
        blocked_languages: Language codes to block.
        mode: "allowlist" or "blocklist".
        action: Action when language restriction triggered.
        threshold: Confidence threshold.
        name: Check name.

    Returns:
        Configured Check instance.

    Example:
        from guardrailgraph.checks import language_check

        # Only allow English and Spanish
        my_lang = language_check(allowed_languages=["en", "es"])
    """
    detector = LanguageDetector(
        allowed_languages=allowed_languages,
        blocked_languages=blocked_languages,
        mode=mode,
    )
    return detector.to_check(name=name, action=action, threshold=threshold)
