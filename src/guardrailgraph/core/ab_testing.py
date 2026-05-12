"""A/B testing for guardrail configurations.

Test different guardrail configurations without redeployment.
Route traffic between pipeline variants and compare metrics.
"""

from __future__ import annotations

import hashlib
import random
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Tuple

from guardrailgraph.core.context import CheckContext
from guardrailgraph.core.pipeline import Pipeline
from guardrailgraph.core.result import PipelineResult


@dataclass
class VariantResult:
    """Result from an A/B test variant."""

    variant_name: str
    pipeline_result: PipelineResult
    is_active: bool  # Whether this variant's decision was used


@dataclass
class ABTestResult:
    """Result from an A/B test execution."""

    active_variant: str
    result: PipelineResult
    all_variants: Dict[str, VariantResult] = field(default_factory=dict)
    test_name: str = ""


@dataclass
class ABTestMetrics:
    """Aggregated metrics for an A/B test."""

    variant_name: str
    total_requests: int = 0
    block_count: int = 0
    pass_count: int = 0
    avg_latency_ms: float = 0.0
    total_latency_ms: float = 0.0

    @property
    def block_rate(self) -> float:
        return self.block_count / max(self.total_requests, 1)

    @property
    def pass_rate(self) -> float:
        return self.pass_count / max(self.total_requests, 1)


class ABTest:
    """A/B test between multiple pipeline configurations.

    Routes traffic between pipeline variants based on configurable
    split ratios. Collects metrics for comparison.

    Args:
        name: Test name for identification.
        variants: Dict mapping variant names to (Pipeline, weight) tuples.
        sticky: Whether to use consistent routing per user/session.
        shadow_mode: If True, run all variants but only use the active one.

    Example:
        test = ABTest(
            name="toxicity-threshold",
            variants={
                "control": (pipeline_strict, 0.5),
                "relaxed": (pipeline_relaxed, 0.5),
            },
        )
        result = test.run("user input")
    """

    def __init__(
        self,
        name: str,
        variants: Dict[str, Tuple[Pipeline, float]],
        sticky: bool = False,
        shadow_mode: bool = False,
    ):
        self.name = name
        self.variants = variants
        self.sticky = sticky
        self.shadow_mode = shadow_mode
        self._metrics: Dict[str, ABTestMetrics] = {
            name: ABTestMetrics(variant_name=name) for name in variants
        }
        self._assignment_cache: Dict[str, str] = {}

    def run(
        self,
        text: str,
        context: Optional[CheckContext] = None,
        user_id: Optional[str] = None,
    ) -> ABTestResult:
        """Execute the A/B test.

        Args:
            text: Text to evaluate.
            context: Optional runtime context.
            user_id: Optional user ID for sticky routing.

        Returns:
            ABTestResult with the active variant's decision.
        """
        # Select active variant
        active_variant = self._select_variant(user_id)

        # Run active variant
        active_pipeline = self.variants[active_variant][0]
        active_result = active_pipeline.run(text, context)

        # Record metrics
        self._record_metrics(active_variant, active_result)

        ab_result = ABTestResult(
            active_variant=active_variant,
            result=active_result,
            test_name=self.name,
        )

        # Shadow mode: run all variants for comparison
        if self.shadow_mode:
            for variant_name, (pipeline, _) in self.variants.items():
                if variant_name == active_variant:
                    ab_result.all_variants[variant_name] = VariantResult(
                        variant_name=variant_name,
                        pipeline_result=active_result,
                        is_active=True,
                    )
                else:
                    shadow_result = pipeline.run(text, context)
                    self._record_metrics(variant_name, shadow_result)
                    ab_result.all_variants[variant_name] = VariantResult(
                        variant_name=variant_name,
                        pipeline_result=shadow_result,
                        is_active=False,
                    )

        return ab_result

    def _select_variant(self, user_id: Optional[str] = None) -> str:
        """Select which variant to use for this request."""
        if self.sticky and user_id:
            if user_id in self._assignment_cache:
                return self._assignment_cache[user_id]

            # Deterministic assignment based on user_id hash
            hash_val = int(hashlib.md5(user_id.encode()).hexdigest(), 16)
            variant = self._weighted_select(hash_val / (2**128))
            self._assignment_cache[user_id] = variant
            return variant

        # Random selection based on weights
        return self._weighted_select(random.random())

    def _weighted_select(self, rand_val: float) -> str:
        """Select variant based on weighted random value."""
        total_weight = sum(w for _, w in self.variants.values())
        cumulative = 0.0

        for name, (_, weight) in self.variants.items():
            cumulative += weight / total_weight
            if rand_val <= cumulative:
                return name

        # Fallback to last variant
        return list(self.variants.keys())[-1]

    def _record_metrics(self, variant_name: str, result: PipelineResult) -> None:
        """Record metrics for a variant."""
        metrics = self._metrics[variant_name]
        metrics.total_requests += 1
        metrics.total_latency_ms += result.total_latency_ms
        metrics.avg_latency_ms = metrics.total_latency_ms / metrics.total_requests

        if result.allowed:
            metrics.pass_count += 1
        else:
            metrics.block_count += 1

    def get_metrics(self) -> Dict[str, ABTestMetrics]:
        """Get current metrics for all variants."""
        return self._metrics.copy()

    def get_winner(self) -> Optional[str]:
        """Determine the winning variant based on metrics.

        Returns the variant with the lowest false-positive rate
        (highest pass rate while still blocking threats).
        Returns None if insufficient data.
        """
        if all(m.total_requests < 10 for m in self._metrics.values()):
            return None

        # Simple heuristic: prefer variant with moderate block rate
        # (too low = missing threats, too high = too many false positives)
        best_variant = None
        best_score = -1.0

        for name, metrics in self._metrics.items():
            if metrics.total_requests < 5:
                continue
            # Score: penalize extreme block rates
            block_rate = metrics.block_rate
            score = 1.0 - abs(block_rate - 0.1)  # Ideal ~10% block rate
            if score > best_score:
                best_score = score
                best_variant = name

        return best_variant


def ab_test(
    name: str,
    variants: Dict[str, Tuple[Pipeline, float]],
    sticky: bool = False,
    shadow_mode: bool = False,
) -> ABTest:
    """Create an A/B test between pipeline configurations.

    Args:
        name: Test name.
        variants: Dict of {name: (pipeline, weight)}.
        sticky: Consistent routing per user.
        shadow_mode: Run all variants, use only active one.

    Returns:
        Configured ABTest instance.

    Example:
        from guardrailgraph.core.ab_testing import ab_test

        test = ab_test(
            name="threshold-experiment",
            variants={
                "strict": (strict_pipeline, 0.5),
                "relaxed": (relaxed_pipeline, 0.5),
            },
            shadow_mode=True,
        )
    """
    return ABTest(name=name, variants=variants, sticky=sticky, shadow_mode=shadow_mode)
