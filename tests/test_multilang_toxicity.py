"""Tests for multi-language toxicity detection."""

import pytest

from guardrailgraph.checks.multilang_toxicity import (
    Language,
    MultiLangToxicityDetector,
    ToxicityResult,
)


@pytest.fixture
def detector():
    """Create a detector with all default languages."""
    return MultiLangToxicityDetector()


@pytest.fixture
def strict_detector():
    """Create a detector with a low threshold."""
    return MultiLangToxicityDetector(threshold=0.1)


class TestLanguageDetection:
    def test_detect_japanese(self, detector):
        assert detector.detect_language("これはテストです") == Language.JAPANESE

    def test_detect_spanish(self, detector):
        assert detector.detect_language("¿Cómo estás?") == Language.SPANISH

    def test_detect_french(self, detector):
        assert detector.detect_language("C'est très bien, ça") == Language.FRENCH

    def test_detect_german(self, detector):
        assert detector.detect_language("Das ist schön") == Language.GERMAN

    def test_detect_english_default(self, detector):
        assert detector.detect_language("Hello world") == Language.ENGLISH


class TestSpanishToxicity:
    def test_detects_spanish_insult(self, detector):
        result = detector.check_text("Eres un idiota", language=Language.SPANISH)
        assert result.is_toxic
        assert "idiota" in result.matched_patterns

    def test_clean_spanish_text(self, detector):
        result = detector.check_text("Buenos dias amigo", language=Language.SPANISH)
        assert not result.is_toxic
        assert result.score == 0.0

    def test_detects_spanish_threats(self, strict_detector):
        result = strict_detector.check_text(
            "te voy a matar", language=Language.SPANISH
        )
        assert result.is_toxic
        assert "threats" in result.categories


class TestFrenchToxicity:
    def test_detects_french_insult(self, detector):
        result = detector.check_text("Tu es un cretin", language=Language.FRENCH)
        assert result.is_toxic
        assert "cretin" in result.matched_patterns

    def test_clean_french_text(self, detector):
        result = detector.check_text("Bonjour le monde", language=Language.FRENCH)
        assert not result.is_toxic


class TestGermanToxicity:
    def test_detects_german_insult(self, detector):
        result = detector.check_text("Du bist ein Dummkopf", language=Language.GERMAN)
        assert result.is_toxic
        assert "dummkopf" in result.matched_patterns

    def test_clean_german_text(self, detector):
        result = detector.check_text("Guten Morgen", language=Language.GERMAN)
        assert not result.is_toxic


class TestJapaneseToxicity:
    def test_detects_japanese_insult(self, detector):
        result = detector.check_text("お前はバカだ", language=Language.JAPANESE)
        assert result.is_toxic
        assert "バカ" in result.matched_patterns

    def test_clean_japanese_text(self, detector):
        result = detector.check_text("今日は良い天気ですね", language=Language.JAPANESE)
        assert not result.is_toxic


class TestMultiLangDetector:
    def test_check_all_languages(self, detector):
        results = detector.check_all_languages("idiota")
        assert "es" in results
        assert "fr" in results
        assert "de" in results
        assert "ja" in results

    def test_custom_patterns(self):
        custom = {Language.SPANISH: {"insults": ["payaso", "menso"]}}
        detector = MultiLangToxicityDetector(custom_patterns=custom)
        result = detector.check_text("Eres un payaso", language=Language.SPANISH)
        assert result.is_toxic
        assert "payaso" in result.matched_patterns

    def test_add_patterns_dynamically(self, detector):
        detector.add_patterns(Language.SPANISH, "insults", ["bobo"])
        result = detector.check_text("Eres un bobo", language=Language.SPANISH)
        assert result.is_toxic
        assert "bobo" in result.matched_patterns

    def test_set_threshold(self, detector):
        detector.set_threshold(0.9)
        assert detector.threshold == 0.9

    def test_invalid_threshold_raises(self, detector):
        with pytest.raises(ValueError):
            detector.set_threshold(1.5)

    def test_supported_languages(self, detector):
        langs = detector.supported_languages
        assert "es" in langs
        assert "fr" in langs
        assert "de" in langs
        assert "ja" in langs

    def test_result_structure(self, detector):
        result = detector.check_text("idiota", language=Language.SPANISH)
        assert isinstance(result, ToxicityResult)
        assert isinstance(result.score, float)
        assert isinstance(result.matched_patterns, list)
        assert isinstance(result.categories, list)
        assert result.language == "es"
