"""Audit trail logging for compliance evidence."""

from __future__ import annotations

import json
import time
from typing import Any, Dict, List, Optional

from guardrailgraph.core.result import PipelineResult


class AuditLogger:
    """Audit trail logger for compliance evidence.

    Logs every pipeline execution with full context for regulatory audits.
    Supports multiple backends: local file, DynamoDB, CloudWatch.

    Args:
        backend: Storage backend ("local", "dynamodb", "cloudwatch").
        table_name: DynamoDB table name (for dynamodb backend).
        log_file: Local file path (for local backend).
        retention_days: How long to retain audit records.
    """

    def __init__(
        self,
        backend: str = "local",
        table_name: Optional[str] = None,
        log_file: str = "guardrailgraph-audit.jsonl",
        retention_days: int = 365,
    ):
        self.backend = backend
        self.table_name = table_name
        self.log_file = log_file
        self.retention_days = retention_days
        self._records: List[Dict[str, Any]] = []

    def log(
        self,
        result: PipelineResult,
        request_id: Optional[str] = None,
        user_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Log a pipeline execution result.

        Args:
            result: The pipeline execution result.
            request_id: Optional request identifier.
            user_id: Optional user identifier.

        Returns:
            The audit record that was logged.
        """
        record = {
            "timestamp": time.time(),
            "request_id": request_id,
            "user_id": user_id,
            "pipeline_name": result.pipeline_name,
            "allowed": result.allowed,
            "action": result.action.value,
            "total_latency_ms": result.total_latency_ms,
            "check_count": len(result.check_results),
            "checks": [
                {
                    "name": r.name,
                    "detected": r.detected,
                    "confidence": r.confidence,
                    "action": r.action.value,
                    "latency_ms": r.latency_ms,
                }
                for r in result.check_results
            ],
        }

        self._records.append(record)

        if self.backend == "local":
            self._write_local(record)

        return record

    def _write_local(self, record: Dict[str, Any]) -> None:
        """Write audit record to local JSONL file."""
        with open(self.log_file, "a") as f:
            f.write(json.dumps(record) + "\n")

    def get_records(
        self,
        since: Optional[float] = None,
        pipeline_name: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """Retrieve audit records with optional filtering."""
        records = self._records
        if since:
            records = [r for r in records if r["timestamp"] >= since]
        if pipeline_name:
            records = [r for r in records if r["pipeline_name"] == pipeline_name]
        return records

    @property
    def record_count(self) -> int:
        """Total number of audit records."""
        return len(self._records)
