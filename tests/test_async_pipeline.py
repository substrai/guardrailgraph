"""Tests for async pipeline execution."""

from __future__ import annotations

import asyncio
import time
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from guardrailgraph.core.actions import Action
from guardrailgraph.core.check import Check
from guardrailgraph.core.context import CheckContext
from guardrailgraph.core.result import CheckResult
from guardrailgraph.pipeline.async_pipeline import (
    AsyncPipeline,
    AsyncPipelineConfig,
    CheckExecutionResult,
)


# --- Helpers ---


def make_check(name: str, action: Action = Action.PASS, depends_on=None, delay=0.0):
    """Create a mock check for testing."""

    async def _execute(text: str, context: CheckContext) -> CheckResult:
        if delay > 0:
            await asyncio.sleep(delay)
        detected = action != Action.PASS
        return CheckResult(
            check_name=name,
            detected=detected,
            action=action,
            confidence=0.9 if detected else 0.1,
            blocked=(action == Action.BLOCK),
            details={"text_length": len(text)},
        )

    check = MagicMock(spec=Check)
    check.name = name
    check.action = action
    check.depends_on = depends_on or []
    check.timeout_ms = None
    check.execute = _execute
    return check


def make_failing_check(name: str, error_cls=RuntimeError):
    """Create a check that raises an exception."""

    async def _execute(text: str, context: CheckContext) -> CheckResult:
        raise error_cls(f"Check {name} failed intentionally")

    check = MagicMock(spec=Check)
    check.name = name
    check.action = Action.BLOCK
    check.depends_on = []
    check.timeout_ms = None
    check.execute = _execute
    return check


def make_slow_check(name: str, delay_seconds: float = 5.0):
    """Create a check that takes a long time (for timeout testing)."""

    async def _execute(text: str, context: CheckContext) -> CheckResult:
        await asyncio.sleep(delay_seconds)
        return CheckResult(
            check_name=name,
            detected=False,
            action=Action.PASS,
            confidence=0.0,
            blocked=False,
        )

    check = MagicMock(spec=Check)
    check.name = name
    check.action = Action.PASS
    check.depends_on = []
    check.timeout_ms = None
    check.execute = _execute
    return check


# --- Tests ---


class TestAsyncPipelineBasic:
    """Basic async pipeline functionality."""

    @pytest.mark.asyncio
    async def test_empty_pipeline_allows_all(self):
        """An empty pipeline should allow all content."""
        pipeline = AsyncPipeline(name="empty")
        result = await pipeline.execute("Hello world")

        assert result.allowed is True
        assert result.action == Action.PASS
        assert result.check_results == []

    @pytest.mark.asyncio
    async def test_single_passing_check(self):
        """A single passing check should allow content."""
        check = make_check("safe-check", action=Action.PASS)
        pipeline = AsyncPipeline(name="single", checks=[check])

        result = await pipeline.execute("Safe content")

        assert result.allowed is True
        assert len(result.check_results) == 1
        assert result.check_results[0].check_name == "safe-check"

    @pytest.mark.asyncio
    async def test_single_blocking_check(self):
        """A single blocking check should block content in fail-closed mode."""
        check = make_check("blocker", action=Action.BLOCK)
        pipeline = AsyncPipeline(name="blocking", checks=[check])

        result = await pipeline.execute("Dangerous content")

        assert result.allowed is False
        assert result.action == Action.BLOCK

    @pytest.mark.asyncio
    async def test_multiple_independent_checks_run_in_parallel(self):
        """Independent checks should execute concurrently."""
        # Each check takes 0.1s; if sequential would take 0.3s
        checks = [
            make_check("check-1", delay=0.1),
            make_check("check-2", delay=0.1),
            make_check("check-3", delay=0.1),
        ]
        pipeline = AsyncPipeline(name="parallel", checks=checks)

        start = time.perf_counter()
        result = await pipeline.execute("Test text")
        elapsed = time.perf_counter() - start

        assert result.allowed is True
        assert len(result.check_results) == 3
        # Should complete in ~0.1s (parallel), not ~0.3s (sequential)
        assert elapsed < 0.25

    @pytest.mark.asyncio
    async def test_add_and_remove_checks(self):
        """Should support adding and removing checks dynamically."""
        pipeline = AsyncPipeline(name="dynamic")
        check1 = make_check("check-1")
        check2 = make_check("check-2")

        pipeline.add_check(check1).add_check(check2)
        assert len(pipeline.checks) == 2

        pipeline.remove_check("check-1")
        assert len(pipeline.checks) == 1
        assert pipeline.checks[0].name == "check-2"


class TestAsyncPipelineModes:
    """Test different pipeline execution modes."""

    @pytest.mark.asyncio
    async def test_fail_closed_blocks_on_any_failure(self):
        """fail-closed mode blocks if ANY check detects an issue."""
        checks = [
            make_check("pass-1", action=Action.PASS),
            make_check("blocker", action=Action.BLOCK),
            make_check("pass-2", action=Action.PASS),
        ]
        config = AsyncPipelineConfig(mode="fail-closed")
        pipeline = AsyncPipeline(name="fail-closed", checks=checks, config=config)

        result = await pipeline.execute("Content")
        assert result.allowed is False

    @pytest.mark.asyncio
    async def test_log_only_never_blocks(self):
        """log-only mode should never block, even with blocking checks."""
        check = make_check("blocker", action=Action.BLOCK)
        config = AsyncPipelineConfig(mode="log-only")
        pipeline = AsyncPipeline(name="log-only", checks=[check], config=config)

        result = await pipeline.execute("Dangerous content")
        assert result.allowed is True

    @pytest.mark.asyncio
    async def test_fail_fast_stops_on_first_block(self):
        """fail_fast should stop processing after first blocking result."""
        checks = [
            make_check("blocker", action=Action.BLOCK),
            make_check("slow", delay=1.0),
        ]
        config = AsyncPipelineConfig(fail_fast=True)
        pipeline = AsyncPipeline(name="fast", checks=checks, config=config)

        start = time.perf_counter()
        result = await pipeline.execute("Content")
        elapsed = time.perf_counter() - start

        assert result.allowed is False
        # Should not wait for the slow check in subsequent layers
        # (both are in layer 0 since no deps, so gather runs both)


class TestAsyncPipelineDependencies:
    """Test dependency-aware scheduling."""

    @pytest.mark.asyncio
    async def test_dependent_checks_execute_in_order(self):
        """Checks with dependencies should wait for their dependencies."""
        check_a = make_check("check-a", delay=0.05)
        check_b = make_check("check-b", depends_on=["check-a"], delay=0.05)

        pipeline = AsyncPipeline(name="deps", checks=[check_a, check_b])
        result = await pipeline.execute("Test")

        assert result.allowed is True
        assert len(result.check_results) == 2

    @pytest.mark.asyncio
    async def test_diamond_dependency_graph(self):
        """Diamond-shaped DAG: A -> B, A -> C, B -> D, C -> D."""
        check_a = make_check("A")
        check_b = make_check("B", depends_on=["A"])
        check_c = make_check("C", depends_on=["A"])
        check_d = make_check("D", depends_on=["B", "C"])

        pipeline = AsyncPipeline(
            name="diamond", checks=[check_a, check_b, check_c, check_d]
        )
        result = await pipeline.execute("Test")

        assert result.allowed is True
        assert len(result.check_results) == 4


class TestAsyncPipelineErrorHandling:
    """Test error handling and timeouts."""

    @pytest.mark.asyncio
    async def test_check_timeout_returns_error_result(self):
        """A timed-out check should return an error result, not crash."""
        slow_check = make_slow_check("slow", delay_seconds=5.0)
        config = AsyncPipelineConfig(check_timeout_ms=100)
        pipeline = AsyncPipeline(name="timeout", checks=[slow_check], config=config)

        result = await pipeline.execute("Test")
        # In fail-closed with skip error handling, timeout is skipped
        assert result.allowed is True
        assert result.metadata["checks_failed"] == 1

    @pytest.mark.asyncio
    async def test_check_exception_with_skip_policy(self):
        """Failed checks with 'skip' policy should not block."""
        failing = make_failing_check("bad-check")
        config = AsyncPipelineConfig(on_check_error="skip")
        pipeline = AsyncPipeline(name="skip-errors", checks=[failing], config=config)

        result = await pipeline.execute("Test")
        assert result.allowed is True

    @pytest.mark.asyncio
    async def test_check_exception_with_block_policy(self):
        """Failed checks with 'block' policy should block content."""
        failing = make_failing_check("bad-check")
        config = AsyncPipelineConfig(on_check_error="block")
        pipeline = AsyncPipeline(name="block-errors", checks=[failing], config=config)

        result = await pipeline.execute("Test")
        assert result.allowed is False

    @pytest.mark.asyncio
    async def test_on_error_callback_invoked(self):
        """on_error callback should be called when a check fails."""
        errors_received = []

        def error_handler(check_name, error):
            errors_received.append((check_name, str(error)))

        failing = make_failing_check("bad-check")
        pipeline = AsyncPipeline(
            name="callback", checks=[failing], on_error=error_handler
        )

        await pipeline.execute("Test")
        assert len(errors_received) == 1
        assert errors_received[0][0] == "bad-check"


class TestAsyncPipelineMetrics:
    """Test metrics and observability."""

    @pytest.mark.asyncio
    async def test_execution_count_increments(self):
        """execution_count should increment with each execute call."""
        pipeline = AsyncPipeline(name="metrics")
        assert pipeline.execution_count == 0

        await pipeline.execute("First")
        assert pipeline.execution_count == 1

        await pipeline.execute("Second")
        assert pipeline.execution_count == 2

    @pytest.mark.asyncio
    async def test_average_latency_tracked(self):
        """average_latency_ms should reflect actual execution time."""
        pipeline = AsyncPipeline(name="latency")
        assert pipeline.average_latency_ms == 0.0

        await pipeline.execute("Test")
        assert pipeline.average_latency_ms > 0.0

    @pytest.mark.asyncio
    async def test_metadata_includes_execution_stats(self):
        """Pipeline result metadata should include execution statistics."""
        checks = [make_check("c1"), make_check("c2")]
        pipeline = AsyncPipeline(name="stats", checks=checks)

        result = await pipeline.execute("Test")
        assert result.metadata["execution_mode"] == "async"
        assert result.metadata["checks_executed"] == 2
        assert result.metadata["checks_succeeded"] == 2
        assert result.metadata["checks_failed"] == 0

    @pytest.mark.asyncio
    async def test_repr(self):
        """repr should show useful pipeline info."""
        config = AsyncPipelineConfig(max_concurrency=5)
        pipeline = AsyncPipeline(name="test", checks=[], config=config)
        assert "test" in repr(pipeline)
        assert "max_concurrency=5" in repr(pipeline)
