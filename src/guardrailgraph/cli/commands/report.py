"""guardrailgraph report — generate compliance reports."""

from __future__ import annotations

import time
from pathlib import Path
from typing import Any


def run(args: Any) -> int:
    """Generate a compliance report."""
    from guardrailgraph.core.config import load_pipeline
    from guardrailgraph.observability.analytics import GuardrailAnalytics
    from guardrailgraph.observability.reports import ReportGenerator

    config_path = getattr(args, "config", "guardrailgraph.yaml")
    framework = getattr(args, "framework", "general")
    output_format = getattr(args, "format", "text")
    output_file = getattr(args, "output", None)

    # Load pipeline
    try:
        pipeline = load_pipeline(config_path)
    except FileNotFoundError:
        print(f"Config not found: {config_path}")
        return 1

    print(f"Generating {framework.upper()} compliance report...")
    print(f"Pipeline: {pipeline.name} ({len(pipeline.checks)} checks)")

    # Generate report
    generator = ReportGenerator(
        pipeline=pipeline,
        analytics=None,  # No live analytics in CLI mode
        framework=framework,
    )
    report = generator.generate()

    # Output
    if output_format == "json":
        content = report.to_json()
    else:
        content = report.to_text()

    if output_file:
        Path(output_file).write_text(content)
        print(f"\nReport saved to: {output_file}")
    else:
        print()
        print(content)

    return 0
