"""Async pipeline execution for non-blocking guardrail checks.

Provides an AsyncPipeline that executes independent guardrail checks in parallel
using asyncio.gather(), enabling non-blocking evaluation of content against
multiple safety policies simultaneously.

Key features:
- Parallel execution of independent checks via asyncio.gather()
- Dependency-aware scheduling (respects check DAG ordering)
- Configurable concurrency limits via semaphore
- Timeout enforcement per-check and per-pipeline
- Graceful degradation on individual check failures
- Streaming results as checks complete
"""

from __future__ import annotations

import asyncio
import time
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any, AsyncIterator, Callable, Dict, List, Optional

from guardrailgraph.core.actions import Action
from guardrailgraph.core.check import Check
from guardrailgraph.core.context import CheckContext
from guardrailgraph.core.result import CheckResult, PipelineResult


@dataclass
class CheckExecutionResult:
    """Result of a single check execution with timing metadata."""

    check_name: str
    result: Optional[CheckResult] = None
    error: Optional[str] = None
    latency_ms: float = 0.0
    timed_out: bool = False

    @property
    def success(self) -> bool:
        return self.result is not None and not self.timed_out


@dataclass
class AsyncPipelineConfig:
    """Configuration for async pipeline execution."""

    max_concurrency: int = 10
    check_timeout_ms: float = 3000
    pipeline_timeout_ms: float = 10000
    fail_fast: bool = False
    mode: str = "fail-closed"
    on_check_error: str = "skip"  # "skip", "block", "raise"
    collect_metrics: bool = True


class AsyncPipeline:
    """Async pipeline that executes guardrail checks in parallel.

    Uses asyncio.gather() for independent checks and respects dependency
    ordering for checks that depend on other checks' results.

    Modes:
        - fail-closed: Block if ANY check fails (default, safest).
        - fail-open: Allow unless ALL checks agree to block.
        - log-only: Never block, only log results.

    Example:
        pipeline = AsyncPipeline(
            name="content-safety",
            checks=[pii_check, toxicity_check, injection_check],
            config=AsyncPipelineConfig(max_concurrency=5),
        )
        result = await pipeline.execute("User input text here")
    """

    def __init__(
        self,
        name: str = "async-pipeline",
        checks: Optional[List[Check]] = None,
        config: Optional[AsyncPipelineConfig] = None,
        on_complete: Optional[Callable] = None,
        on_error: Optional[Callable] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ):
        self.name = name
        self.checks: List[Check] = checks or []
        self.config = config or AsyncPipelineConfig()
        self.on_complete = on_complete
        self.on_error = on_error
        self.metadata = metadata or {}
        self._semaphore: Optional[asyncio.Semaphore] = None
        self._execution_count: int = 0
        self._total_latency_ms: float = 0.0

    def add_check(self, check: Check) -> "AsyncPipeline":
        """Add a check to the pipeline. Returns self for chaining."""
        if not isinstance(check, Check):
            raise TypeError(f"Expected Check instance, got {type(check).__name__}")
        self.checks.append(check)
        return self

    def remove_check(self, name: str) -> "AsyncPipeline":
        """Remove a check by name."""
        self.checks = [c for c in self.checks if c.name != name]
        return self

    async def execute(
        self,
        text: str,
        context: Optional[CheckContext] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> PipelineResult:
        """Execute all checks asynchronously with parallel independent checks.

        Args:
            text: The text content to evaluate.
            context: Optional runtime context for checks.
            metadata: Optional per-request metadata.

        Returns:
            PipelineResult with all check outcomes and final decision.
        """
        start = time.perf_counter()
        self._execution_count += 1

        ctx = context or CheckContext(pipeline_name=self.name)
        if metadata:
            ctx.metadata.update(metadata)

        # Initialize semaphore for concurrency control
        self._semaphore = asyncio.Semaphore(self.config.max_concurrency)

        # Build execution layers (topological sort)
        layers = self._build_execution_layers()

        all_results: List[CheckResult] = []
        execution_details: List[CheckExecutionResult] = []
        current_text = text
        blocked = False

        try:
            # Apply pipeline-level timeout
            async with asyncio.timeout(self.config.pipeline_timeout_ms / 1000):
                for layer in layers:
                    if blocked and self.config.fail_fast:
                        break

                    # Execute all checks in this layer in parallel
                    layer_exec_results = await self._execute_layer(
                        layer, current_text, ctx
                    )
                    execution_details.extend(layer_exec_results)

                    # Process layer results
                    for exec_result in layer_exec_results:
                        if exec_result.success:
                            result = exec_result.result
                            all_results.append(result)

                            # Apply redactions
                            if (
                                result.detected
                                and result.action == Action.REDACT
                                and result.redacted_text
                            ):
                                current_text = result.redacted_text

                            # Check for blocking
                            if result.blocked and self.config.mode != "log-only":
                                blocked = True
                                if self.config.fail_fast:
                                    break
                        else:
                            # Handle check failure based on config
                            blocked = self._handle_check_error(
                                exec_result, blocked
                            )

        except asyncio.TimeoutError:
            # Pipeline timeout - decide based on mode
            if self.config.mode == "fail-closed":
                blocked = True

        # Determine final action
        final_action = self._determine_final_action(all_results)
        allowed = not blocked if self.config.mode != "log-only" else True

        total_latency = (time.perf_counter() - start) * 1000
        self._total_latency_ms += total_latency

        pipeline_result = PipelineResult(
            allowed=allowed,
            action=final_action,
            check_results=all_results,
            modified_text=current_text if current_text != text else None,
            original_text=text,
            total_latency_ms=total_latency,
            pipeline_name=self.name,
            metadata={
                **self.metadata,
                "execution_mode": "async",
                "checks_executed": len(execution_details),
                "checks_succeeded": sum(1 for e in execution_details if e.success),
                "checks_failed": sum(1 for e in execution_details if not e.success),
            },
        )

        # Fire callbacks
        if self.on_complete:
            if asyncio.iscoroutinefunction(self.on_complete):
                await self.on_complete(pipeline_result)
            else:
                self.on_complete(pipeline_result)

        return pipeline_result

    async def execute_streaming(
        self,
        text: str,
        context: Optional[CheckContext] = None,
    ) -> AsyncIterator[CheckExecutionResult]:
        """Execute checks and yield results as they complete.

        Useful for real-time monitoring of check progress.

        Args:
            text: The text content to evaluate.
            context: Optional runtime context.

        Yields:
            CheckExecutionResult as each check completes.
        """
        ctx = context or CheckContext(pipeline_name=self.name)
        self._semaphore = asyncio.Semaphore(self.config.max_concurrency)

        layers = self._build_execution_layers()

        for layer in layers:
            # Create tasks for all checks in this layer
            tasks = {
                asyncio.create_task(
                    self._execute_single_check(check, text, ctx)
                ): check
                for check in layer
            }

            # Yield results as they complete
            for coro in asyncio.as_completed(tasks.keys()):
                exec_result = await coro
                yield exec_result

    async def _execute_layer(
        self,
        layer: List[Check],
        text: str,
        context: CheckContext,
    ) -> List[CheckExecutionResult]:
        """Execute all checks in a layer concurrently using asyncio.gather().

        Args:
            layer: List of independent checks to run in parallel.
            text: The text to evaluate.
            context: Runtime context.

        Returns:
            List of execution results for all checks in the layer.
        """
        if not layer:
            return []

        tasks = [
            self._execute_single_check(check, text, context)
            for check in layer
        ]

        # asyncio.gather runs all tasks concurrently
        results = await asyncio.gather(*tasks, return_exceptions=False)
        return list(results)

    async def _execute_single_check(
        self,
        check: Check,
        text: str,
        context: CheckContext,
    ) -> CheckExecutionResult:
        """Execute a single check with timeout and error handling.

        Uses a semaphore to limit concurrency and applies per-check timeout.
        """
        start = time.perf_counter()

        async with self._semaphore:
            try:
                timeout_sec = (
                    check.timeout_ms / 1000
                    if check.timeout_ms
                    else self.config.check_timeout_ms / 1000
                )

                async with asyncio.timeout(timeout_sec):
                    result = await check.execute(text, context)

                latency = (time.perf_counter() - start) * 1000
                return CheckExecutionResult(
                    check_name=check.name,
                    result=result,
                    latency_ms=latency,
                )

            except asyncio.TimeoutError:
                latency = (time.perf_counter() - start) * 1000
                return CheckExecutionResult(
                    check_name=check.name,
                    error=f"Check '{check.name}' timed out after {timeout_sec*1000:.0f}ms",
                    latency_ms=latency,
                    timed_out=True,
                )

            except Exception as e:
                latency = (time.perf_counter() - start) * 1000
                error_msg = f"Check '{check.name}' failed: {type(e).__name__}: {e}"

                if self.on_error:
                    if asyncio.iscoroutinefunction(self.on_error):
                        await self.on_error(check.name, e)
                    else:
                        self.on_error(check.name, e)

                return CheckExecutionResult(
                    check_name=check.name,
                    error=error_msg,
                    latency_ms=latency,
                )

    def _build_execution_layers(self) -> List[List[Check]]:
        """Build execution layers using topological sort (Kahn's algorithm).

        Checks with no dependencies go in layer 0.
        Checks depending on layer-0 checks go in layer 1, etc.
        Independent checks within the same layer execute in parallel.
        """
        if not self.checks:
            return []

        check_map = {c.name: c for c in self.checks}
        in_degree: Dict[str, int] = {c.name: 0 for c in self.checks}
        dependents: Dict[str, List[str]] = defaultdict(list)

        for c in self.checks:
            for dep in c.depends_on:
                if dep in check_map:
                    in_degree[c.name] += 1
                    dependents[dep].append(c.name)

        # Kahn's algorithm
        layers: List[List[Check]] = []
        ready = [name for name, deg in in_degree.items() if deg == 0]

        while ready:
            layer = [check_map[name] for name in ready]
            layers.append(layer)

            next_ready = []
            for name in ready:
                for dep_name in dependents[name]:
                    in_degree[dep_name] -= 1
                    if in_degree[dep_name] == 0:
                        next_ready.append(dep_name)
            ready = next_ready

        return layers

    def _handle_check_error(
        self, exec_result: CheckExecutionResult, currently_blocked: bool
    ) -> bool:
        """Handle a check execution error based on configuration.

        Returns updated blocked state.
        """
        if self.config.on_check_error == "block":
            return True
        elif self.config.on_check_error == "raise":
            raise RuntimeError(exec_result.error)
        # "skip" - do not change blocked state
        return currently_blocked

    def _determine_final_action(self, results: List[CheckResult]) -> Action:
        """Determine the most severe action from all check results."""
        severity = {
            Action.BLOCK: 4,
            Action.FLAG_FOR_REVIEW: 3,
            Action.REDACT: 2,
            Action.LOG: 1,
            Action.PASS: 0,
        }

        max_action = Action.PASS
        max_severity = 0

        for result in results:
            if result.detected:
                s = severity.get(result.action, 0)
                if s > max_severity:
                    max_severity = s
                    max_action = result.action

        return max_action

    @property
    def execution_count(self) -> int:
        """Total number of pipeline executions."""
        return self._execution_count

    @property
    def average_latency_ms(self) -> float:
        """Average pipeline execution latency."""
        if self._execution_count == 0:
            return 0.0
        return self._total_latency_ms / self._execution_count

    def __repr__(self) -> str:
        return (
            f"AsyncPipeline(name={self.name!r}, "
            f"checks={len(self.checks)}, "
            f"max_concurrency={self.config.max_concurrency})"
        )
