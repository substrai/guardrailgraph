"""guardrailgraph validate — validate pipeline configuration."""

from __future__ import annotations

from typing import Any, List


def run(args: Any) -> int:
    """Validate a guardrailgraph.yaml configuration file."""
    from guardrailgraph.core.config import load_config, build_pipeline_from_config

    config_path = args.config
    errors: List[str] = []
    warnings: List[str] = []

    print(f"Validating: {config_path}")
    print("-" * 40)

    # Load config
    try:
        config = load_config(config_path)
    except FileNotFoundError:
        print(f"  ✗ File not found: {config_path}")
        return 1
    except Exception as e:
        print(f"  ✗ Invalid YAML: {e}")
        return 1

    print("  ✓ Valid YAML syntax")

    # Check required sections
    if "pipeline" not in config:
        errors.append("Missing 'pipeline' section")
    else:
        pipeline_config = config["pipeline"]
        mode = pipeline_config.get("mode", "")
        if mode not in ("fail-closed", "fail-open", "log-only"):
            errors.append(f"Invalid pipeline mode: '{mode}' "
                         f"(must be fail-closed, fail-open, or log-only)")
        else:
            print(f"  ✓ Pipeline mode: {mode}")

    if "checks" not in config:
        warnings.append("No checks defined — pipeline will pass everything")
    else:
        checks = config["checks"]
        print(f"  ✓ {len(checks)} check(s) defined")

        # Validate each check
        valid_actions = {"pass", "block", "redact", "flag_for_review", "log"}
        for i, check_def in enumerate(checks):
            name = check_def.get("name", f"check-{i}")
            action = check_def.get("action", "block")
            check_type = check_def.get("type", "")

            if not check_type:
                errors.append(f"Check '{name}': missing 'type' field")
            if action not in valid_actions:
                errors.append(f"Check '{name}': invalid action '{action}'")

    # Try building the pipeline
    try:
        pipeline = build_pipeline_from_config(config)
        print(f"  ✓ Pipeline builds successfully ({len(pipeline.checks)} checks loaded)")
    except Exception as e:
        errors.append(f"Pipeline build failed: {e}")

    # Report
    print()
    if errors:
        print(f"❌ {len(errors)} error(s):")
        for err in errors:
            print(f"   • {err}")
    if warnings:
        print(f"⚠️  {len(warnings)} warning(s):")
        for warn in warnings:
            print(f"   • {warn}")
    if not errors and not warnings:
        print("✅ Configuration is valid!")

    return 1 if errors else 0
