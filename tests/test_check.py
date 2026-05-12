"""Tests for the @check decorator and Check class."""

import pytest
from guardrailgraph import check, Check, Action, CheckResult


class TestCheckDecorator:
    """Test the @check decorator."""

    def test_basic_check_creation(self):
        """@check creates a Check instance."""
        @check(name="test-check", action=Action.BLOCK)
        def my_check(text: str) -> dict:
            return {"detected": "bad" in text, "confidence": 0.9}

        assert isinstance(my_check, Check)
        assert my_check.name == "test-check"
        assert my_check.action == Action.BLOCK

    def test_check_detects_violation(self):
        """Check correctly detects a violation."""
        @check(name="bad-word", action=Action.BLOCK, threshold=0.5)
        def detect_bad(text: str) -> dict:
            return {"detected": "bad" in text, "confidence": 0.9}

        result = detect_bad("this is bad content")
        assert isinstance(result, CheckResult)
        assert result.detected is True
        assert result.confidence == 0.9
        assert result.action == Action.BLOCK

    def test_check_passes_safe_text(self):
        """Check passes safe text."""
        @check(name="bad-word", action=Action.BLOCK, threshold=0.5)
        def detect_bad(text: str) -> dict:
            return {"detected": "bad" in text, "confidence": 0.0}

        result = detect_bad("this is good content")
        assert result.detected is False
        assert result.action == Action.PASS

    def test_check_threshold(self):
        """Check respects confidence threshold."""
        @check(name="low-conf", action=Action.BLOCK, threshold=0.8)
        def low_confidence(text: str) -> dict:
            return {"detected": True, "confidence": 0.5}

        result = low_confidence("anything")
        # Confidence 0.5 < threshold 0.8, so not triggered
        assert result.detected is False
        assert result.action == Action.PASS

    def test_check_with_redaction(self):
        """Check can return redacted text."""
        @check(name="redactor", action=Action.REDACT)
        def redact_check(text: str) -> dict:
            return {
                "detected": True,
                "confidence": 1.0,
                "redacted_text": text.replace("secret", "[REDACTED]"),
            }

        result = redact_check("this is a secret message")
        assert result.detected is True
        assert result.action == Action.REDACT
        assert result.redacted_text == "this is a [REDACTED] message"

    def test_check_default_name(self):
        """Check uses function name as default."""
        @check(action=Action.BLOCK)
        def my_custom_check(text: str) -> dict:
            return {"detected": False, "confidence": 0.0}

        assert my_custom_check.name == "my-custom-check"

    def test_check_bool_return(self):
        """Check handles boolean return values."""
        @check(name="bool-check", action=Action.BLOCK)
        def bool_check(text: str) -> bool:
            return "danger" in text

        result = bool_check("danger ahead")
        assert result.detected is True
        assert result.action == Action.BLOCK

    def test_check_error_handling(self):
        """Check handles errors gracefully."""
        @check(name="error-check", action=Action.BLOCK)
        def error_check(text: str) -> dict:
            raise ValueError("Something went wrong")

        result = error_check("test")
        assert result.detected is False
        assert result.action == Action.PASS
        assert result.error is not None

    def test_check_depends_on(self):
        """Check stores dependency information."""
        @check(name="dependent", action=Action.BLOCK, depends_on=["pii-check"])
        def dependent_check(text: str) -> dict:
            return {"detected": False, "confidence": 0.0}

        assert dependent_check.depends_on == ["pii-check"]

    def test_check_tags(self):
        """Check stores tags."""
        @check(name="tagged", action=Action.BLOCK, tags=["pii", "hipaa"])
        def tagged_check(text: str) -> dict:
            return {"detected": False, "confidence": 0.0}

        assert tagged_check.tags == ["pii", "hipaa"]
