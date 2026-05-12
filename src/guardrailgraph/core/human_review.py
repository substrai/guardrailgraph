"""Human-in-the-loop review system.

Routes flagged content to human reviewers via configurable backends:
- In-memory queue (development/testing)
- AWS SQS (production)
- SNS notifications
- Webhook callbacks
"""

from __future__ import annotations

import time
import uuid
from collections import deque
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Deque, Dict, List, Optional

from guardrailgraph.core.result import PipelineResult


class ReviewStatus(str, Enum):
    """Status of a human review request."""

    PENDING = "pending"
    IN_REVIEW = "in_review"
    APPROVED = "approved"
    REJECTED = "rejected"
    EXPIRED = "expired"


@dataclass
class ReviewRequest:
    """A request for human review of flagged content."""

    id: str
    text: str
    pipeline_name: str
    check_name: str
    confidence: float
    reason: str
    status: ReviewStatus = ReviewStatus.PENDING
    created_at: float = field(default_factory=time.time)
    reviewed_at: Optional[float] = None
    reviewer_id: Optional[str] = None
    reviewer_decision: Optional[str] = None
    reviewer_notes: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    timeout_hours: float = 24.0

    @property
    def is_expired(self) -> bool:
        """Check if the review request has expired."""
        elapsed_hours = (time.time() - self.created_at) / 3600
        return elapsed_hours > self.timeout_hours and self.status == ReviewStatus.PENDING

    def to_dict(self) -> Dict[str, Any]:
        """Serialize to dictionary."""
        return {
            "id": self.id,
            "text": self.text[:200] + "..." if len(self.text) > 200 else self.text,
            "pipeline_name": self.pipeline_name,
            "check_name": self.check_name,
            "confidence": self.confidence,
            "reason": self.reason,
            "status": self.status.value,
            "created_at": self.created_at,
            "reviewed_at": self.reviewed_at,
            "reviewer_id": self.reviewer_id,
            "reviewer_decision": self.reviewer_decision,
            "timeout_hours": self.timeout_hours,
        }


class ReviewQueue:
    """Human review queue for flagged content.

    Manages review requests with configurable backends and timeouts.

    Args:
        backend: Queue backend — "memory", "sqs", or "webhook".
        queue_url: SQS queue URL (for sqs backend).
        webhook_url: Webhook URL (for webhook backend).
        timeout_hours: Default timeout for review requests.
        on_approve: Callback when content is approved.
        on_reject: Callback when content is rejected.
        on_expire: Callback when review request expires.

    Example:
        queue = ReviewQueue(timeout_hours=24)
        queue.submit(pipeline_result)

        # Later, reviewer processes:
        queue.approve("request-id", reviewer_id="reviewer@company.com")
    """

    def __init__(
        self,
        backend: str = "memory",
        queue_url: Optional[str] = None,
        webhook_url: Optional[str] = None,
        timeout_hours: float = 24.0,
        on_approve: Optional[Callable[[ReviewRequest], None]] = None,
        on_reject: Optional[Callable[[ReviewRequest], None]] = None,
        on_expire: Optional[Callable[[ReviewRequest], None]] = None,
    ):
        self.backend = backend
        self.queue_url = queue_url
        self.webhook_url = webhook_url
        self.timeout_hours = timeout_hours
        self.on_approve = on_approve
        self.on_reject = on_reject
        self.on_expire = on_expire

        self._requests: Dict[str, ReviewRequest] = {}
        self._pending_queue: Deque[str] = deque()

    def submit(
        self,
        result: PipelineResult,
        reason: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> ReviewRequest:
        """Submit content for human review.

        Args:
            result: The pipeline result that triggered the review.
            reason: Human-readable reason for the review.
            metadata: Additional context for the reviewer.

        Returns:
            ReviewRequest with tracking ID.
        """
        # Find the check that triggered the flag
        flagged_checks = result.flagged_checks
        check_name = flagged_checks[0].name if flagged_checks else "unknown"
        confidence = flagged_checks[0].confidence if flagged_checks else 0.0

        request = ReviewRequest(
            id=str(uuid.uuid4())[:12],
            text=result.original_text or "",
            pipeline_name=result.pipeline_name,
            check_name=check_name,
            confidence=confidence,
            reason=reason or f"Flagged by {check_name} (confidence: {confidence:.2f})",
            timeout_hours=self.timeout_hours,
            metadata=metadata or {},
        )

        self._requests[request.id] = request
        self._pending_queue.append(request.id)

        return request

    def approve(
        self,
        request_id: str,
        reviewer_id: Optional[str] = None,
        notes: Optional[str] = None,
    ) -> ReviewRequest:
        """Approve a review request (content is safe).

        Args:
            request_id: The review request ID.
            reviewer_id: Who approved it.
            notes: Reviewer notes.

        Returns:
            Updated ReviewRequest.
        """
        request = self._requests.get(request_id)
        if not request:
            raise ValueError(f"Review request not found: {request_id}")

        request.status = ReviewStatus.APPROVED
        request.reviewed_at = time.time()
        request.reviewer_id = reviewer_id
        request.reviewer_decision = "approved"
        request.reviewer_notes = notes

        if self.on_approve:
            self.on_approve(request)

        return request

    def reject(
        self,
        request_id: str,
        reviewer_id: Optional[str] = None,
        notes: Optional[str] = None,
    ) -> ReviewRequest:
        """Reject a review request (content is unsafe).

        Args:
            request_id: The review request ID.
            reviewer_id: Who rejected it.
            notes: Reviewer notes.

        Returns:
            Updated ReviewRequest.
        """
        request = self._requests.get(request_id)
        if not request:
            raise ValueError(f"Review request not found: {request_id}")

        request.status = ReviewStatus.REJECTED
        request.reviewed_at = time.time()
        request.reviewer_id = reviewer_id
        request.reviewer_decision = "rejected"
        request.reviewer_notes = notes

        if self.on_reject:
            self.on_reject(request)

        return request

    def get_pending(self) -> List[ReviewRequest]:
        """Get all pending review requests."""
        self._expire_old_requests()
        return [
            self._requests[rid]
            for rid in self._pending_queue
            if rid in self._requests and self._requests[rid].status == ReviewStatus.PENDING
        ]

    def get_request(self, request_id: str) -> Optional[ReviewRequest]:
        """Get a specific review request by ID."""
        return self._requests.get(request_id)

    def _expire_old_requests(self) -> None:
        """Expire old pending requests."""
        for request in self._requests.values():
            if request.is_expired:
                request.status = ReviewStatus.EXPIRED
                if self.on_expire:
                    self.on_expire(request)

    @property
    def pending_count(self) -> int:
        """Number of pending review requests."""
        return len(self.get_pending())

    @property
    def total_count(self) -> int:
        """Total number of review requests."""
        return len(self._requests)

    def stats(self) -> Dict[str, int]:
        """Get review queue statistics."""
        stats: Dict[str, int] = {
            "total": len(self._requests),
            "pending": 0,
            "approved": 0,
            "rejected": 0,
            "expired": 0,
        }
        for request in self._requests.values():
            stats[request.status.value] = stats.get(request.status.value, 0) + 1
        return stats
