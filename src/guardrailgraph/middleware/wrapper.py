"""Convenience decorators for wrapping LLM calls with guardrails."""

from __future__ import annotations

import functools
from typing import Any, Callable, Dict, Optional

from guardrailgraph.core.pipeline import Pipeline
from guardrailgraph.middleware.base import GuardrailMiddleware


def guardrail(
    pipeline: Pipeline,
    apply_to: str = "both",
    on_block_response: Optional[str] = None,
) -> Callable:
    """Decorator to add guardrails to any function.

    Args:
        pipeline: The guardrail pipeline to apply.
        apply_to: "input", "output", or "both".
        on_block_response: Custom blocked response.

    Example:
        @guardrail(pipeline=my_pipeline)
        def my_llm_call(prompt: str) -> str:
            return bedrock.invoke(prompt)
    """
    middleware = GuardrailMiddleware(
        pipeline=pipeline,
        apply_to=apply_to,
        on_block_response=on_block_response,
    )

    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        def wrapper(text: str, *args: Any, **kwargs: Any) -> Dict[str, Any]:
            # Check input
            input_result = middleware.process_input(text)
            if not input_result.allowed:
                return {
                    "blocked": True,
                    "response": middleware.on_block_response,
                    "guardrail_result": input_result.to_dict(),
                }

            # Call the wrapped function
            effective_text = input_result.modified_text or text
            result = func(effective_text, *args, **kwargs)

            # Check output
            response_text = result if isinstance(result, str) else str(result)
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
            }

        return wrapper
    return decorator


def wrap_llm_call(
    llm_call: Callable,
    pipeline: Pipeline,
    apply_to: str = "both",
) -> Callable:
    """Wrap any LLM call function with guardrails.

    Args:
        llm_call: The LLM function to wrap.
        pipeline: Guardrail pipeline to apply.
        apply_to: "input", "output", or "both".

    Returns:
        Wrapped function with guardrails.

    Example:
        safe_invoke = wrap_llm_call(bedrock.invoke, my_pipeline)
        result = safe_invoke("user prompt")
    """
    middleware = GuardrailMiddleware(pipeline=pipeline, apply_to=apply_to)
    return middleware.wrap(llm_call)
