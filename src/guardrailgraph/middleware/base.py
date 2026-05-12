"""Base middleware class for LLM provider integration."""

from __future__ import annotations

from typing import Any, Callable, Dict, Optional

from guardrailgraph.core.context import CheckContext
from guardrailgraph.core.pipeline import Pipeline
from guardrailgraph.core.result import PipelineResult


class GuardrailMiddleware:
    """Middleware that wraps LLM calls with guardrail checks.

    Applies guardrails to both input (before LLM call) and output
    (after LLM response), configurable per pipeline.

    Args:
        pipeline: The guardrail pipeline to apply.
        apply_to: Where to apply checks — "input", "output", or "both".
        on_block_response: Custom response when content is blocked.

    Example:
        middleware = GuardrailMiddleware(
            pipeline=my_pipeline,
            apply_to="both",
        )

        # Wrap any LLM call
        result = middleware.process_input("user prompt")
        if result.allowed:
            llm_response = call_llm(result.modified_text or "user prompt")
            output_result = middleware.process_output(llm_response)
    """

    def __init__(
        self,
        pipeline: Pipeline,
        apply_to: str = "both",
        on_block_response: Optional[str] = None,
    ):
        self.pipeline = pipeline
        self.apply_to = apply_to
        self.on_block_response = (
            on_block_response
            or "I cannot process this request due to content policy."
        )

    def process_input(
        self,
        text: str,
        context: Optional[CheckContext] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> PipelineResult:
        """Run guardrails on input text (before LLM call).

        Args:
            text: User input/prompt to check.
            context: Optional runtime context.
            metadata: Optional request metadata.

        Returns:
            PipelineResult — check result.allowed before proceeding.
        """
        if self.apply_to in ("input", "both"):
            return self.pipeline.run(text, context, metadata)

        # If not checking input, return a pass-through result
        from guardrailgraph.core.actions import Action
        return PipelineResult(
            allowed=True,
            action=Action.PASS,
            original_text=text,
            pipeline_name=self.pipeline.name,
        )

    def process_output(
        self,
        text: str,
        context: Optional[CheckContext] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> PipelineResult:
        """Run guardrails on output text (after LLM response).

        Args:
            text: LLM response to check.
            context: Optional runtime context.
            metadata: Optional request metadata.

        Returns:
            PipelineResult — use modified_text if redaction occurred.
        """
        if self.apply_to in ("output", "both"):
            return self.pipeline.run(text, context, metadata)

        from guardrailgraph.core.actions import Action
        return PipelineResult(
            allowed=True,
            action=Action.PASS,
            original_text=text,
            pipeline_name=self.pipeline.name,
        )

    def wrap(self, llm_call: Callable) -> Callable:
        """Wrap an LLM call function with guardrails.

        Args:
            llm_call: Function that takes text and returns LLM response.

        Returns:
            Wrapped function with input/output guardrails.
        """
        middleware = self

        def wrapped(text: str, **kwargs: Any) -> Dict[str, Any]:
            # Check input
            input_result = middleware.process_input(text)
            if not input_result.allowed:
                return {
                    "blocked": True,
                    "response": middleware.on_block_response,
                    "guardrail_result": input_result.to_dict(),
                }

            # Call LLM with potentially modified text
            effective_text = input_result.modified_text or text
            llm_response = llm_call(effective_text, **kwargs)

            # Check output
            response_text = (
                llm_response if isinstance(llm_response, str)
                else str(llm_response)
            )
            output_result = middleware.process_output(response_text)

            if not output_result.allowed:
                return {
                    "blocked": True,
                    "response": middleware.on_block_response,
                    "guardrail_result": output_result.to_dict(),
                }

            return {
                "blocked": False,
                "response": output_result.modified_text or response_text,
                "guardrail_result": {
                    "input": input_result.to_dict(),
                    "output": output_result.to_dict(),
                },
            }

        return wrapped
