"""Pipeline builder and DAG executor — the orchestration engine."""

from __future__ import annotations

import asyncio
import time
from collections import defaultdict
from typing import Any, Callable, Dict, List, Optional, Union

from guardrailgraph.core.actions import Action
from guardrailgraph.core.check import Check
from guardrailgraph.core.context import CheckContext
from guardrailgraph.core.result import CheckResult, PipelineResult


class Pipeline:
    """A composable guardrail pipeline that executes checks as a DAG.

    Checks without dependencies run in parallel. Checks with `depends_on`
    wait for their dependencies to complete first.

    Modes:
        - fail-closed: Block if ANY check fails (default, safest).
        - fail-open: Allow unless ALL checks agree to block.
        - log-only: Never block, only log results (canary mode).

    Example:
        my_pipeline = pipeline(
            name="healthcare-chatbot",
            checks=[detect_pii, check_toxicity, restrict_topics],
            mode="fail-closed",
        )
        result = my_pipeline.run("Patient John Smith has diabetes")
    """

    def __init__(
        self,
        name: str = "default",
        checks: Optional[List[Check]] = None,
        packs: Optional[List[Any]] = None,
        mode: str = "fail-closed",
        timeout_ms: float = 5000,
        on_block: Optional[Callable] = None,
        on_flag: Optional[Callable] = None,
        on_pass: Optional[Callable] = None,
        parallel: bool = True,
        metadata: Optional[Dict[str, Any]] = None,
    ):
        self.name = name
        self.checks: List[Check] = []
        self.mode = mode
        self.timeout_ms = timeout_ms
        self.on_block = on_block
        self.on_flag = on_flag
        self.on_pass = on_pass
        self.parallel = parallel
        self.metadata = metadata or {}
        self._hooks: Dict[str, List[Callable]] = defaultdict(list)

        # Register checks
        if checks:
            for c in checks:
                self.add_check(c)

        # Register packs (each pack provides a list of checks)
        if packs:
            for pack in packs:
                if hasattr(pack, "checks"):
                    for c in pack.checks:
                        self.add_check(c)
                elif isinstance(pack, list):
                    for c in pack:
                        self.add_check(c)

    def add_check(self, check: Check) -> "Pipeline":
        """Add a check to the pipeline."""
        if not isinstance(check, Check):
            raise TypeError(f"Expected Check instance, got {type(check).__name__}")
        self.checks.append(check)
        return self

    def remove_check(self, name: str) -> "Pipeline":
        """Remove a check by name."""
        self.checks = [c for c in self.checks if c.name != name]
        return self

    def hook(self, event: str) -> Callable:
        """Register a hook for pipeline events (before_run, after_run, on_block)."""
        def decorator(func: Callable) -> Callable:
            self._hooks[event].append(func)
            return func
        return decorator

    def run(
        self,
        text: str,
        context: Optional[CheckContext] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> PipelineResult:
        """Execute the pipeline synchronously.

        Args:
            text: The text to evaluate.
            context: Optional runtime context.
            metadata: Optional request metadata.

        Returns:
            PipelineResult with all check outcomes and final decision.
        """
        try:
            loop = asyncio.get_event_loop()
            if loop.is_running():
                import concurrent.futures
                with concurrent.futures.ThreadPoolExecutor() as pool:
                    future = pool.submit(
                        asyncio.run, self.run_async(text, context, metadata)
                    )
                    return future.result()
            else:
                return loop.run_until_complete(self.run_async(text, context, metadata))
        except RuntimeError:
            return asyncio.run(self.run_async(text, context, metadata))

    async def run_async(
        self,
        text: str,
        context: Optional[CheckContext] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> PipelineResult:
        """Execute the pipeline asynchronously with DAG scheduling.

        Independent checks run in parallel. Dependent checks wait for
        their dependencies to complete.
        """
        start = time.perf_counter()
        ctx = context or CheckContext(pipeline_name=self.name)
        if metadata:
            ctx.metadata.update(metadata)

        # Fire before_run hooks
        await self._fire_hooks("before_run", text=text, context=ctx)

        # Build execution plan (topological sort)
        execution_layers = self._build_execution_plan()

        all_results: List[CheckResult] = []
        current_text = text
        blocked = False

        for layer in execution_layers:
            if blocked and self.mode == "fail-closed":
                break

            if self.parallel and len(layer) > 1:
                # Execute independent checks in parallel
                tasks = [
                    check.execute(current_text, ctx)
                    for check in layer
                ]
                layer_results = await asyncio.gather(*tasks)
            else:
                # Execute sequentially
                layer_results = []
                for check in layer:
                    result = await check.execute(current_text, ctx)
                    layer_results.append(result)

            # Process results
            for result in layer_results:
                all_results.append(result)

                # Apply redactions to text for subsequent checks
                if result.detected and result.action == Action.REDACT and result.redacted_text:
                    current_text = result.redacted_text

                # Check for blocking
                if result.blocked and self.mode != "log-only":
                    blocked = True

        # Determine final action
        final_action = self._determine_final_action(all_results)
        allowed = not blocked if self.mode != "log-only" else True

        pipeline_result = PipelineResult(
            allowed=allowed,
            action=final_action,
            check_results=all_results,
            modified_text=current_text if current_text != text else None,
            original_text=text,
            total_latency_ms=(time.perf_counter() - start) * 1000,
            pipeline_name=self.name,
            metadata=self.metadata,
        )

        # Fire callbacks
        if not allowed and self.on_block:
            self.on_block(pipeline_result)
        elif pipeline_result.flagged_checks and self.on_flag:
            self.on_flag(pipeline_result)
        elif allowed and self.on_pass:
            self.on_pass(pipeline_result)

        # Fire after_run hooks
        await self._fire_hooks("after_run", result=pipeline_result)

        return pipeline_result

    def _build_execution_plan(self) -> List[List[Check]]:
        """Build execution layers using topological sort.

        Checks with no dependencies go in layer 0.
        Checks depending on layer-0 checks go in layer 1, etc.
        """
        if not self.checks:
            return []

        # Build dependency graph
        check_map = {c.name: c for c in self.checks}
        in_degree: Dict[str, int] = {c.name: 0 for c in self.checks}
        dependents: Dict[str, List[str]] = defaultdict(list)

        for c in self.checks:
            for dep in c.depends_on:
                if dep in check_map:
                    in_degree[c.name] += 1
                    dependents[dep].append(c.name)

        # Kahn's algorithm for topological layers
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

    async def _fire_hooks(self, event: str, **kwargs: Any) -> None:
        """Fire registered hooks for an event."""
        for hook in self._hooks.get(event, []):
            if asyncio.iscoroutinefunction(hook):
                await hook(**kwargs)
            else:
                hook(**kwargs)

    def __repr__(self) -> str:
        return (
            f"Pipeline(name={self.name!r}, checks={len(self.checks)}, "
            f"mode={self.mode!r})"
        )


def pipeline(
    name: str = "default",
    checks: Optional[List[Check]] = None,
    packs: Optional[List[Any]] = None,
    mode: str = "fail-closed",
    timeout_ms: float = 5000,
    on_block: Optional[Callable] = None,
    on_flag: Optional[Callable] = None,
    on_pass: Optional[Callable] = None,
    parallel: bool = True,
    metadata: Optional[Dict[str, Any]] = None,
) -> Pipeline:
    """Create a guardrail pipeline.

    This is the primary API for defining a guardrail pipeline.

    Args:
        name: Pipeline name for identification and logging.
        checks: List of Check instances to execute.
        packs: Industry compliance packs (each provides checks).
        mode: Execution mode — "fail-closed", "fail-open", or "log-only".
        timeout_ms: Maximum pipeline execution time.
        on_block: Callback when content is blocked.
        on_flag: Callback when content is flagged for review.
        on_pass: Callback when content passes all checks.
        parallel: Whether to run independent checks in parallel.
        metadata: Additional pipeline metadata.

    Returns:
        Configured Pipeline instance.

    Example:
        from guardrailgraph import pipeline, Action
        from guardrailgraph.checks import pii, toxicity

        my_pipeline = pipeline(
            name="my-app",
            checks=[pii.detect(), toxicity.score()],
            mode="fail-closed",
        )
        result = my_pipeline.run("Hello world")
    """
    return Pipeline(
        name=name,
        checks=checks,
        packs=packs,
        mode=mode,
        timeout_ms=timeout_ms,
        on_block=on_block,
        on_flag=on_flag,
        on_pass=on_pass,
        parallel=parallel,
        metadata=metadata,
    )
