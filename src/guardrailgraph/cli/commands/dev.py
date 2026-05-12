"""guardrailgraph dev — local development server for testing guardrails."""

from __future__ import annotations

import json
from typing import Any


def run(args: Any) -> int:
    """Start a local dev server for interactive guardrail testing."""
    from guardrailgraph.core.config import load_pipeline

    port = args.port

    try:
        pipeline = load_pipeline()
        print(f"Loaded pipeline: {pipeline.name} ({len(pipeline.checks)} checks)")
    except FileNotFoundError:
        print("No guardrailgraph.yaml found. Run 'guardrailgraph init' first.")
        return 1

    print(f"\nGuardrailGraph Dev Server")
    print(f"Pipeline: {pipeline.name} | Mode: {pipeline.mode}")
    print(f"Checks: {', '.join(c.name for c in pipeline.checks)}")
    print(f"\nEnter text to test (Ctrl+C to exit):")
    print("-" * 50)

    try:
        while True:
            text = input("\n> ")
            if not text.strip():
                continue

            result = pipeline.run(text)

            # Display result
            status = "✅ PASS" if result.allowed else "❌ BLOCKED"
            print(f"\n{status} | Action: {result.action.value} | "
                  f"Latency: {result.total_latency_ms:.1f}ms")

            for check_result in result.check_results:
                icon = "🚫" if check_result.blocked else "✓"
                print(f"  {icon} {check_result.name}: "
                      f"confidence={check_result.confidence:.2f} "
                      f"action={check_result.action.value}")

            if result.modified_text:
                print(f"\n  Redacted: {result.modified_text}")

    except (KeyboardInterrupt, EOFError):
        print("\n\nDev server stopped.")
        return 0
