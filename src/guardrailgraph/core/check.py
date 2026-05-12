"""The @check decorator — turns Python functions into guardrail checks."""

from __future__ import annotations

import asyncio
import functools
import inspect
import time
from typing import Any, Callable, Dict, List, Optional, Union

from guardrailgraph.core.actions import Action
from guardrailgraph.core.context import CheckContext
from guardrailgraph.core.result import CheckResult


class Check:
    """A guardrail check that evaluates text against a safety policy.

    Wraps a user-defined function and provides:
    - Consistent result format (CheckResult)
    - Threshold-based triggering
    - Timing/latency measurement
    - Error handling with graceful degradation
    - Async execution support

    Example:
        @check(name="pii-detection", action=Action.REDACT)
        def detect_pii(text: str) -> dict:
            entities = find_pii(text)
            return {
                "detected": len(entities) > 0,
                "confidence": 0.95,
                "entities": entities,
                "redacted_text": redact(text, entities),
            }
    """

    def __init__(
        self,
        func: Callable,
        name: str,
        action: Action = Action.BLOCK,
        threshold: float = 0.5,
        description: str = "",
        tags: Optional[List[str]] = None,
        depends_on: Optional[List[str]] = None,
        timeout_ms: Optional[float] = None,
    ):
        self.func = func
        self.name = name
        self.action = action
        self.threshold = threshold
        self.description = description or (func.__doc__ or "").strip()
        self.tags = tags or []
        self.depends_on = depends_on or []
        self.timeout_ms = timeout_ms
        self._is_async = inspect.iscoroutinefunction(func)

        # Preserve function metadata
        functools.update_wrapper(self, func)

    async def execute(
        self,
        text: str,
        context: Optional[CheckContext] = None,
    ) -> CheckResult:
        """Execute the check against the given text.

        Args:
            text: The text to evaluate.
            context: Optional runtime context.

        Returns:
            CheckResult with detection outcome, confidence, and action.
        """
        start = time.perf_counter()
        ctx = context or CheckContext()

        try:
            # Call the check function
            if self._is_async:
                raw_result = await self._call_func(text, ctx)
            else:
                raw_result = await asyncio.get_event_loop().run_in_executor(
                    None, self._call_func_sync, text, ctx
                )

            # Normalize the result
            result = self._normalize_result(raw_result, text)
            result.latency_ms = (time.perf_counter() - start) * 1000
            return result

        except asyncio.TimeoutError:
            return CheckResult(
                name=self.name,
                detected=False,
                confidence=0.0,
                action=Action.PASS,
                latency_ms=(time.perf_counter() - start) * 1000,
                error="Check timed out",
            )
        except Exception as e:
            return CheckResult(
                name=self.name,
                detected=False,
                confidence=0.0,
                action=Action.PASS,
                latency_ms=(time.perf_counter() - start) * 1000,
                error=f"Check failed: {str(e)}",
            )

    def execute_sync(
        self,
        text: str,
        context: Optional[CheckContext] = None,
    ) -> CheckResult:
        """Synchronous execution wrapper."""
        try:
            loop = asyncio.get_event_loop()
            if loop.is_running():
                # If already in an async context, create a new task
                import concurrent.futures
                with concurrent.futures.ThreadPoolExecutor() as pool:
                    future = pool.submit(asyncio.run, self.execute(text, context))
                    return future.result()
            else:
                return loop.run_until_complete(self.execute(text, context))
        except RuntimeError:
            return asyncio.run(self.execute(text, context))

    async def _call_func(self, text: str, ctx: CheckContext) -> Any:
        """Call the async check function with appropriate arguments."""
        sig = inspect.signature(self.func)
        params = list(sig.parameters.keys())

        kwargs: Dict[str, Any] = {}
        if len(params) >= 1:
            kwargs[params[0]] = text
        if len(params) >= 2:
            kwargs[params[1]] = ctx

        return await self.func(**kwargs)

    def _call_func_sync(self, text: str, ctx: CheckContext) -> Any:
        """Call the sync check function with appropriate arguments."""
        sig = inspect.signature(self.func)
        params = list(sig.parameters.keys())

        kwargs: Dict[str, Any] = {}
        if len(params) >= 1:
            kwargs[params[0]] = text
        if len(params) >= 2:
            kwargs[params[1]] = ctx

        return self.func(**kwargs)

    def _normalize_result(self, raw: Any, text: str) -> CheckResult:
        """Normalize a raw check function return value into a CheckResult."""
        if isinstance(raw, CheckResult):
            raw.name = self.name
            return raw

        if isinstance(raw, dict):
            detected = raw.get("detected", False)
            confidence = raw.get("confidence", 1.0 if detected else 0.0)

            # Apply threshold
            triggered = detected and confidence >= self.threshold

            return CheckResult(
                name=self.name,
                detected=triggered,
                confidence=confidence,
                action=self.action if triggered else Action.PASS,
                details={k: v for k, v in raw.items()
                         if k not in ("detected", "confidence", "redacted_text")},
                redacted_text=raw.get("redacted_text"),
            )

        if isinstance(raw, bool):
            return CheckResult(
                name=self.name,
                detected=raw,
                confidence=1.0 if raw else 0.0,
                action=self.action if raw else Action.PASS,
            )

        # Fallback: treat truthy values as detected
        return CheckResult(
            name=self.name,
            detected=bool(raw),
            confidence=1.0 if raw else 0.0,
            action=self.action if raw else Action.PASS,
        )

    def __call__(self, text: str, context: Optional[CheckContext] = None) -> CheckResult:
        """Allow direct synchronous invocation."""
        return self.execute_sync(text, context)

    def __repr__(self) -> str:
        return f"Check(name={self.name!r}, action={self.action.value!r}, threshold={self.threshold})"


def check(
    name: Optional[str] = None,
    action: Action = Action.BLOCK,
    threshold: float = 0.5,
    description: str = "",
    tags: Optional[List[str]] = None,
    depends_on: Optional[List[str]] = None,
    timeout_ms: Optional[float] = None,
) -> Callable:
    """Decorator to define a guardrail check.

    Args:
        name: Unique name for the check. Defaults to function name.
        action: Action to take when check triggers (BLOCK, REDACT, etc.).
        threshold: Minimum confidence score to trigger the action.
        description: Human-readable description of what this check does.
        tags: Tags for categorization (e.g., ["pii", "hipaa"]).
        depends_on: Names of checks that must run before this one.
        timeout_ms: Maximum execution time in milliseconds.

    Example:
        @check(name="toxicity", action=Action.BLOCK, threshold=0.8)
        def check_toxicity(text: str) -> dict:
            score = model.predict(text)
            return {"detected": score > 0.8, "confidence": score}
    """

    def decorator(func: Callable) -> Check:
        check_name = name or func.__name__.replace("_", "-")
        return Check(
            func=func,
            name=check_name,
            action=action,
            threshold=threshold,
            description=description,
            tags=tags,
            depends_on=depends_on,
            timeout_ms=timeout_ms,
        )

    return decorator
