"""Multi-language toxicity detection for GuardrailGraph.

Extends toxicity checking beyond English with language-specific patterns
for Spanish, French, German, and Japanese.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Tuple


class Language(str, Enum):
    """Supported languages for toxicity detection."""

    ENGLISH = "en"
    SPANISH = "es"
    FRENCH = "fr"
    GERMAN = "de"
    JAPANESE = "ja"


@dataclass
class ToxicityResult:
    """Result of a toxicity check."""

    is_toxic: bool
    score: float
    language: str
    matched_patterns: List[str] = field(default_factory=list)
    categories: List[str] = field(default_factory=list)
    details: Dict[str, Any] = field(default_factory=dict)


@dataclass
class LanguageConfig:
    """Configuration for a specific language's toxicity detection."""

    language: Language
    toxic_patterns: List[str] = field(default_factory=list)
    severity_weights: Dict[str, float] = field(default_factory=dict)
    category_patterns: Dict[str, List[str]] = field(default_factory=dict)
    case_sensitive: bool = False
    use_word_boundaries: bool = True


# Default toxic patterns per language (minimal set for demonstration)
DEFAULT_PATTERNS: Dict[Language, Dict[str, List[str]]] = {
    Language.SPANISH: {
        "insults": ["idiota", "estupido", "imbecil", "tonto", "basura"],
        "hate_speech": ["odio", "maldito", "desgraciado"],
        "threats": ["te voy a matar", "te arrepentiras", "venganza"],
    },
    Language.FRENCH: {
        "insults": ["idiot", "stupide", "imbecile", "cretin", "abruti"],
        "hate_speech": ["haine", "maudit", "sale"],
        "threats": ["je vais te tuer", "tu vas payer", "vengeance"],
    },
    Language.GERMAN: {
        "insults": ["idiot", "dummkopf", "blodmann", "trottel", "depp"],
        "hate_speech": ["hass", "verdammt", "dreckig"],
        "threats": ["ich werde dich umbringen", "du wirst bezahlen", "rache"],
    },
    Language.JAPANESE: {
        "insults": ["バカ", "アホ", "クソ", "死ね", "うざい"],
        "hate_speech": ["殺す", "差別", "ヘイト"],
        "threats": ["殺してやる", "許さない", "復讐"],
    },
}

# Severity weights for categories
DEFAULT_SEVERITY: Dict[str, float] = {
    "insults": 0.4,
    "hate_speech": 0.8,
    "threats": 1.0,
}


class MultiLangToxicityDetector:
    """Detects toxicity across multiple languages.

    Supports configurable word lists and patterns per language with
    category-based severity scoring.
    """

    def __init__(
        self,
        languages: Optional[List[Language]] = None,
        threshold: float = 0.3,
        custom_patterns: Optional[Dict[Language, Dict[str, List[str]]]] = None,
        severity_weights: Optional[Dict[str, float]] = None,
    ):
        """Initialize the multi-language toxicity detector.

        Args:
            languages: Languages to check. Defaults to all supported.
            threshold: Score threshold above which text is considered toxic.
            custom_patterns: Additional patterns to merge with defaults.
            severity_weights: Custom severity weights per category.
        """
        self.languages = languages or list(Language)
        self.threshold = threshold
        self.severity_weights = severity_weights or DEFAULT_SEVERITY.copy()
        self._configs: Dict[Language, LanguageConfig] = {}

        # Initialize language configs
        for lang in self.languages:
            if lang == Language.ENGLISH:
                continue  # English handled by base toxicity check
            patterns = DEFAULT_PATTERNS.get(lang, {})
            if custom_patterns and lang in custom_patterns:
                # Merge custom patterns with defaults
                for category, words in custom_patterns[lang].items():
                    if category in patterns:
                        patterns[category] = list(set(patterns[category] + words))
                    else:
                        patterns[category] = words

            config = LanguageConfig(
                language=lang,
                category_patterns=patterns,
                severity_weights=self.severity_weights,
                case_sensitive=(lang == Language.JAPANESE),
                use_word_boundaries=(lang != Language.JAPANESE),
            )
            self._configs[lang] = config

    def detect_language(self, text: str) -> Language:
        """Simple language detection based on character analysis.

        This is a basic heuristic; for production, use a proper detection library.
        """
        # Check for Japanese characters
        if re.search(r'[\u3000-\u303f\u3040-\u309f\u30a0-\u30ff\uff00-\uffef\u4e00-\u9faf]', text):
            return Language.JAPANESE

        # Check for Spanish-specific characters/patterns
        if re.search(r'[ñáéíóú¿¡]', text, re.IGNORECASE):
            return Language.SPANISH

        # Check for French-specific patterns
        if re.search(r'[àâçéèêëïîôùûü]|(?:qu\'|l\'|d\'|j\')', text, re.IGNORECASE):
            return Language.FRENCH

        # Check for German-specific characters
        if re.search(r'[äöüß]|(?:sch|ch)', text, re.IGNORECASE):
            return Language.GERMAN

        return Language.ENGLISH

    def check_text(
        self, text: str, language: Optional[Language] = None
    ) -> ToxicityResult:
        """Check text for toxicity in the specified or detected language.

        Args:
            text: The text to check.
            language: Language to check in. Auto-detected if not specified.

        Returns:
            ToxicityResult with score and matched patterns.
        """
        if language is None:
            language = self.detect_language(text)

        if language == Language.ENGLISH or language not in self._configs:
            return ToxicityResult(
                is_toxic=False,
                score=0.0,
                language=language.value,
                details={"note": "Language not configured for multi-lang check"},
            )

        config = self._configs[language]
        matched_patterns: List[str] = []
        matched_categories: Set[str] = set()
        total_score = 0.0
        max_possible_score = 0.0

        for category, patterns in config.category_patterns.items():
            category_weight = config.severity_weights.get(category, 0.5)
            max_possible_score += category_weight

            for pattern in patterns:
                if self._match_pattern(text, pattern, config):
                    matched_patterns.append(pattern)
                    matched_categories.add(category)
                    total_score += category_weight / len(patterns)

        # Normalize score to 0-1 range
        if max_possible_score > 0:
            normalized_score = min(total_score / max_possible_score, 1.0)
        else:
            normalized_score = 0.0

        # Apply a boost if multiple categories matched
        if len(matched_categories) > 1:
            normalized_score = min(normalized_score * 1.3, 1.0)

        return ToxicityResult(
            is_toxic=normalized_score >= self.threshold,
            score=round(normalized_score, 4),
            language=language.value,
            matched_patterns=matched_patterns,
            categories=sorted(matched_categories),
            details={
                "patterns_checked": sum(
                    len(p) for p in config.category_patterns.values()
                ),
                "categories_matched": len(matched_categories),
            },
        )

    def check_all_languages(self, text: str) -> Dict[str, ToxicityResult]:
        """Check text against all configured languages.

        Returns results per language, useful for multilingual content.
        """
        results = {}
        for lang in self.languages:
            if lang == Language.ENGLISH:
                continue
            results[lang.value] = self.check_text(text, language=lang)
        return results

    def add_patterns(
        self, language: Language, category: str, patterns: List[str]
    ) -> None:
        """Add new toxic patterns for a language and category."""
        if language not in self._configs:
            config = LanguageConfig(
                language=language,
                category_patterns={category: patterns},
                severity_weights=self.severity_weights,
            )
            self._configs[language] = config
        else:
            config = self._configs[language]
            if category in config.category_patterns:
                existing = set(config.category_patterns[category])
                existing.update(patterns)
                config.category_patterns[category] = list(existing)
            else:
                config.category_patterns[category] = patterns

    def set_threshold(self, threshold: float) -> None:
        """Update the toxicity threshold."""
        if not 0.0 <= threshold <= 1.0:
            raise ValueError("Threshold must be between 0.0 and 1.0")
        self.threshold = threshold

    def _match_pattern(
        self, text: str, pattern: str, config: LanguageConfig
    ) -> bool:
        """Check if a pattern matches in the text."""
        flags = 0 if config.case_sensitive else re.IGNORECASE
        if config.use_word_boundaries:
            regex = r'\b' + re.escape(pattern) + r'\b'
        else:
            regex = re.escape(pattern)
        return bool(re.search(regex, text, flags))

    @property
    def supported_languages(self) -> List[str]:
        """Get list of configured language codes."""
        return [lang.value for lang in self._configs.keys()]
