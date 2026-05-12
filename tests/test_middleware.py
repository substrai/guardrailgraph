"""Tests for middleware integration layer."""

import pytest
from guardrailgraph import pipeline, check, Action
from guardrailgraph.middleware import GuardrailMiddleware, guardrail, wrap_llm_call


class TestMiddleware:
    """Test GuardrailMiddleware."""

    def _make_pipeline(self):
        @check(name="blocker", action=Action.BLOCK)
        def block_bad(text: str) -> dict:
            return {"detected": "bad" in text, "confidence": 0.9}

        return pipeline(name="test", checks=[block_bad])

    def test_process_input_blocks(self):
        """Middleware blocks bad input."""
        mw = GuardrailMiddleware(self._make_pipeline(), apply_to="input")
        result = mw.process_input("this is bad content")
        assert not result.allowed

    def test_process_input_passes(self):
        """Middleware passes good input."""
        mw = GuardrailMiddleware(self._make_pipeline(), apply_to="input")
        result = mw.process_input("this is good content")
        assert result.allowed

    def test_process_output(self):
        """Middleware checks output."""
        mw = GuardrailMiddleware(self._make_pipeline(), apply_to="output")
        result = mw.process_output("this is bad output")
        assert not result.allowed

    def test_apply_to_both(self):
        """Middleware checks both input and output."""
        mw = GuardrailMiddleware(self._make_pipeline(), apply_to="both")
        assert not mw.process_input("bad input").allowed
        assert not mw.process_output("bad output").allowed

    def test_wrap_function(self):
        """Middleware wraps LLM call function."""
        mw = GuardrailMiddleware(self._make_pipeline(), apply_to="both")

        def fake_llm(text: str) -> str:
            return f"Response to: {text}"

        wrapped = mw.wrap(fake_llm)

        # Good input
        result = wrapped("hello")
        assert result["blocked"] is False
        assert "Response to: hello" in result["response"]

        # Bad input
        result = wrapped("bad request")
        assert result["blocked"] is True


class TestGuardrailDecorator:
    """Test @guardrail decorator."""

    def test_decorator_blocks_bad_input(self):
        @check(name="blocker", action=Action.BLOCK)
        def block_bad(text: str) -> dict:
            return {"detected": "bad" in text, "confidence": 0.9}

        p = pipeline(name="test", checks=[block_bad])

        @guardrail(pipeline=p)
        def my_llm(text: str) -> str:
            return f"Response: {text}"

        result = my_llm("bad input")
        assert result["blocked"] is True

    def test_decorator_passes_good_input(self):
        @check(name="blocker", action=Action.BLOCK)
        def block_bad(text: str) -> dict:
            return {"detected": "bad" in text, "confidence": 0.9}

        p = pipeline(name="test", checks=[block_bad])

        @guardrail(pipeline=p)
        def my_llm(text: str) -> str:
            return f"Response: {text}"

        result = my_llm("good input")
        assert result["blocked"] is False


class TestWrapLlmCall:
    """Test wrap_llm_call utility."""

    def test_wraps_function(self):
        @check(name="blocker", action=Action.BLOCK)
        def block_bad(text: str) -> dict:
            return {"detected": "bad" in text, "confidence": 0.9}

        p = pipeline(name="test", checks=[block_bad])

        def fake_llm(text: str) -> str:
            return f"LLM says: {text}"

        safe_llm = wrap_llm_call(fake_llm, p)

        result = safe_llm("hello")
        assert result["blocked"] is False

        result = safe_llm("bad stuff")
        assert result["blocked"] is True
