"""Tests for the Pipeline builder and DAG executor."""

import pytest
from guardrailgraph import pipeline, check, Action, Pipeline, CheckResult, PipelineResult


class TestPipeline:
    """Test pipeline creation and execution."""

    def test_create_empty_pipeline(self):
        """Empty pipeline passes everything."""
        p = pipeline(name="empty")
        result = p.run("any text")
        assert result.allowed is True
        assert result.action == Action.PASS

    def test_pipeline_with_single_check(self):
        """Pipeline with one check works."""
        @check(name="blocker", action=Action.BLOCK)
        def always_block(text: str) -> dict:
            return {"detected": True, "confidence": 1.0}

        p = pipeline(name="test", checks=[always_block])
        result = p.run("anything")
        assert result.allowed is False
        assert result.action == Action.BLOCK

    def test_pipeline_passes_safe_text(self):
        """Pipeline passes text that doesn't trigger checks."""
        @check(name="safe-check", action=Action.BLOCK)
        def safe_check(text: str) -> dict:
            return {"detected": False, "confidence": 0.0}

        p = pipeline(name="test", checks=[safe_check])
        result = p.run("hello world")
        assert result.allowed is True

    def test_pipeline_multiple_checks(self):
        """Pipeline runs multiple checks."""
        @check(name="check-1", action=Action.BLOCK)
        def check1(text: str) -> dict:
            return {"detected": False, "confidence": 0.0}

        @check(name="check-2", action=Action.BLOCK)
        def check2(text: str) -> dict:
            return {"detected": False, "confidence": 0.0}

        p = pipeline(name="multi", checks=[check1, check2])
        result = p.run("safe text")
        assert result.allowed is True
        assert len(result.check_results) == 2

    def test_pipeline_fail_closed(self):
        """fail-closed mode blocks on any check failure."""
        @check(name="pass-check", action=Action.BLOCK)
        def pass_check(text: str) -> dict:
            return {"detected": False, "confidence": 0.0}

        @check(name="fail-check", action=Action.BLOCK)
        def fail_check(text: str) -> dict:
            return {"detected": True, "confidence": 1.0}

        p = pipeline(name="test", checks=[pass_check, fail_check], mode="fail-closed")
        result = p.run("test")
        assert result.allowed is False

    def test_pipeline_log_only_mode(self):
        """log-only mode never blocks."""
        @check(name="blocker", action=Action.BLOCK)
        def blocker(text: str) -> dict:
            return {"detected": True, "confidence": 1.0}

        p = pipeline(name="test", checks=[blocker], mode="log-only")
        result = p.run("test")
        assert result.allowed is True  # Never blocks in log-only

    def test_pipeline_redaction(self):
        """Pipeline applies redactions."""
        @check(name="redactor", action=Action.REDACT)
        def redactor(text: str) -> dict:
            return {
                "detected": True,
                "confidence": 1.0,
                "redacted_text": text.replace("secret", "[REDACTED]"),
            }

        p = pipeline(name="test", checks=[redactor])
        result = p.run("this is a secret")
        assert result.allowed is True  # Redact doesn't block
        assert result.modified_text == "this is a [REDACTED]"

    def test_pipeline_latency_tracking(self):
        """Pipeline tracks total latency."""
        @check(name="fast", action=Action.BLOCK)
        def fast_check(text: str) -> dict:
            return {"detected": False, "confidence": 0.0}

        p = pipeline(name="test", checks=[fast_check])
        result = p.run("test")
        assert result.total_latency_ms > 0

    def test_pipeline_on_block_callback(self):
        """on_block callback fires when content is blocked."""
        callback_called = []

        @check(name="blocker", action=Action.BLOCK)
        def blocker(text: str) -> dict:
            return {"detected": True, "confidence": 1.0}

        p = pipeline(
            name="test",
            checks=[blocker],
            on_block=lambda r: callback_called.append(True),
        )
        p.run("test")
        assert len(callback_called) == 1

    def test_pipeline_dag_dependencies(self):
        """Checks with depends_on run after their dependencies."""
        execution_order = []

        @check(name="first", action=Action.BLOCK)
        def first_check(text: str) -> dict:
            execution_order.append("first")
            return {"detected": False, "confidence": 0.0}

        @check(name="second", action=Action.BLOCK, depends_on=["first"])
        def second_check(text: str) -> dict:
            execution_order.append("second")
            return {"detected": False, "confidence": 0.0}

        p = pipeline(name="dag", checks=[second_check, first_check], parallel=False)
        p.run("test")
        assert execution_order == ["first", "second"]

    def test_pipeline_result_to_dict(self):
        """PipelineResult serializes to dict."""
        @check(name="test", action=Action.BLOCK)
        def test_check(text: str) -> dict:
            return {"detected": False, "confidence": 0.0}

        p = pipeline(name="test", checks=[test_check])
        result = p.run("hello")
        d = result.to_dict()
        assert "allowed" in d
        assert "action" in d
        assert "check_results" in d
        assert "timestamp" in d

    def test_pipeline_add_remove_check(self):
        """Can add and remove checks dynamically."""
        @check(name="dynamic", action=Action.BLOCK)
        def dynamic_check(text: str) -> dict:
            return {"detected": True, "confidence": 1.0}

        p = pipeline(name="test")
        assert len(p.checks) == 0

        p.add_check(dynamic_check)
        assert len(p.checks) == 1

        p.remove_check("dynamic")
        assert len(p.checks) == 0
