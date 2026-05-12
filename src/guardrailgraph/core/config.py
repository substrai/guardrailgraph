"""YAML configuration loader for guardrailgraph.yaml files."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml

from guardrailgraph.core.actions import Action
from guardrailgraph.core.check import Check
from guardrailgraph.core.pipeline import Pipeline


# Built-in check type registry
BUILTIN_CHECKS = {
    "builtin/pii": "guardrailgraph.checks.pii:pii_check",
    "builtin/toxicity": "guardrailgraph.checks.toxicity:toxicity_check",
    "builtin/topics": "guardrailgraph.checks.topics:topic_check",
    "builtin/injection": "guardrailgraph.checks.injection:injection_check",
    "builtin/cost": "guardrailgraph.checks.cost:cost_check",
}


def load_config(path: str = "guardrailgraph.yaml") -> Dict[str, Any]:
    """Load and parse a guardrailgraph.yaml configuration file.

    Args:
        path: Path to the YAML config file.

    Returns:
        Parsed configuration dictionary.

    Raises:
        FileNotFoundError: If config file doesn't exist.
        yaml.YAMLError: If config is invalid YAML.
    """
    config_path = Path(path)
    if not config_path.exists():
        raise FileNotFoundError(f"Config file not found: {path}")

    with open(config_path) as f:
        config = yaml.safe_load(f)

    return config or {}


def build_pipeline_from_config(
    config: Dict[str, Any],
    environment: Optional[str] = None,
) -> Pipeline:
    """Build a Pipeline from a parsed configuration dictionary.

    Args:
        config: Parsed YAML configuration.
        environment: Environment override (dev/staging/prod).

    Returns:
        Configured Pipeline instance.
    """
    # Extract pipeline settings
    pipeline_config = config.get("pipeline", {})
    project_config = config.get("project", {})

    mode = pipeline_config.get("mode", "fail-closed")
    timeout_ms = pipeline_config.get("timeout_ms", 5000)
    parallel = pipeline_config.get("parallel", True)

    # Apply environment overrides
    if environment:
        env_config = config.get("environments", {}).get(environment, {})
        if "mode" in env_config:
            mode = env_config["mode"]

    # Build checks from config
    checks: List[Check] = []
    check_configs = config.get("checks", [])

    for check_def in check_configs:
        check_instance = _build_check_from_config(check_def, environment, config)
        if check_instance:
            checks.append(check_instance)

    return Pipeline(
        name=project_config.get("name", "default"),
        checks=checks,
        mode=mode,
        timeout_ms=timeout_ms,
        parallel=parallel,
    )


def _build_check_from_config(
    check_def: Dict[str, Any],
    environment: Optional[str],
    full_config: Dict[str, Any],
) -> Optional[Check]:
    """Build a single Check from its YAML definition."""
    check_type = check_def.get("type", "")
    check_name = check_def.get("name", "unnamed")
    action_str = check_def.get("action", "block")
    config = check_def.get("config", {})

    # Apply environment overrides for this check
    if environment:
        env_checks = (
            full_config.get("environments", {})
            .get(environment, {})
            .get("checks", {})
        )
        if check_name in env_checks:
            config.update(env_checks[check_name])

    # Map action string to Action enum
    action_map = {
        "pass": Action.PASS,
        "block": Action.BLOCK,
        "redact": Action.REDACT,
        "flag_for_review": Action.FLAG_FOR_REVIEW,
        "log": Action.LOG,
    }
    action = action_map.get(action_str, Action.BLOCK)
    threshold = config.get("threshold", config.get("confidence_threshold", 0.5))

    # Resolve built-in checks
    if check_type.startswith("builtin/"):
        return _resolve_builtin(check_type, check_name, action, threshold, config)

    return None


def _resolve_builtin(
    check_type: str,
    name: str,
    action: Action,
    threshold: float,
    config: Dict[str, Any],
) -> Optional[Check]:
    """Resolve a built-in check type to a Check instance."""
    from guardrailgraph.checks.pii import pii_check
    from guardrailgraph.checks.toxicity import toxicity_check
    from guardrailgraph.checks.topics import topic_check
    from guardrailgraph.checks.injection import injection_check
    from guardrailgraph.checks.cost import cost_check

    if check_type == "builtin/pii":
        return pii_check(
            entity_types=config.get("entity_types"),
            redaction_char=config.get("redaction_char", "X"),
            sensitivity=config.get("sensitivity", "high"),
            action=action,
            threshold=threshold,
            name=name,
        )
    elif check_type == "builtin/toxicity":
        return toxicity_check(
            categories=config.get("categories"),
            threshold=threshold,
            action=action,
            name=name,
        )
    elif check_type == "builtin/topics":
        return topic_check(
            blocked_topics=config.get("blocked_topics", []),
            allowed_topics=config.get("allowed_topics"),
            mode=config.get("mode", "blocklist"),
            action=action,
            threshold=threshold,
            name=name,
        )
    elif check_type == "builtin/injection":
        return injection_check(
            detection_methods=config.get("detection_methods"),
            sensitivity=config.get("sensitivity", "high"),
            action=action,
            threshold=threshold,
            name=name,
        )
    elif check_type == "builtin/cost":
        return cost_check(
            max_tokens_per_request=config.get("max_tokens_per_request", 4000),
            max_cost_per_request=config.get("max_cost_per_session", 0.10),
            action=action,
            threshold=threshold,
            name=name,
        )

    return None


def load_pipeline(
    path: str = "guardrailgraph.yaml",
    environment: Optional[str] = None,
) -> Pipeline:
    """Load a pipeline directly from a YAML config file.

    Convenience function combining load_config + build_pipeline_from_config.

    Args:
        path: Path to guardrailgraph.yaml.
        environment: Environment to use (dev/staging/prod).

    Returns:
        Configured Pipeline instance.

    Example:
        from guardrailgraph.core.config import load_pipeline

        pipeline = load_pipeline("guardrailgraph.yaml", environment="prod")
        result = pipeline.run("Check this text")
    """
    config = load_config(path)
    return build_pipeline_from_config(config, environment)
