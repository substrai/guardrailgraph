"""Check execution context — provides runtime info to checks."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, Optional


@dataclass
class CheckContext:
    """Runtime context passed to check functions.

    Provides access to pipeline configuration, metadata, and shared
    resources (knowledge bases, external services) during check execution.

    Attributes:
        pipeline_name: Name of the executing pipeline.
        environment: Current environment (dev/staging/prod).
        config: Check-specific configuration from YAML.
        metadata: Request metadata (user_id, session_id, etc.).
        knowledge_base: Optional knowledge base for hallucination checks.
        shared: Shared state between checks in the same pipeline run.
    """

    pipeline_name: str = ""
    environment: str = "dev"
    config: Dict[str, Any] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)
    knowledge_base: Optional[Any] = None
    shared: Dict[str, Any] = field(default_factory=dict)

    def get(self, key: str, default: Any = None) -> Any:
        """Get a value from config or metadata."""
        if key in self.config:
            return self.config[key]
        return self.metadata.get(key, default)
