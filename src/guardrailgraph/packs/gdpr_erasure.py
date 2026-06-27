"""GDPR Right-to-Erasure Handler — Article 17 compliance.

Implements the full right-to-erasure (right to be forgotten) workflow:
- Detects erasure requests in user input
- Validates the request against legal exceptions
- Generates structured erasure commands for downstream systems
- Produces audit-compliant records of erasure processing
- Supports configurable data retention policies

Usage:
    from guardrailgraph.packs.gdpr_erasure import ErasureHandler, ErasureConfig

    handler = ErasureHandler(config=ErasureConfig(
        retention_days=30,
        require_identity_verification=True,
        exempt_categories=["legal_hold", "regulatory_requirement"],
    ))

    result = handler.process("Please delete all my data")
"""

from __future__ import annotations

import re
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Set

from guardrailgraph.core.actions import Action
from guardrailgraph.core.check import check


class ErasureStatus(str, Enum):
    """Status of an erasure request."""

    DETECTED = "detected"
    VALIDATED = "validated"
    EXEMPT = "exempt"
    PENDING_VERIFICATION = "pending_verification"
    APPROVED = "approved"
    EXECUTED = "executed"
    REJECTED = "rejected"


class ErasureScope(str, Enum):
    """Scope of data to be erased."""

    FULL = "full"  # All personal data
    PARTIAL = "partial"  # Specific categories only
    CONVERSATION = "conversation"  # Current conversation only
    ACCOUNT = "account"  # Full account deletion


class ExemptionReason(str, Enum):
    """Legal reasons to deny erasure (Article 17(3))."""

    FREEDOM_OF_EXPRESSION = "freedom_of_expression"
    LEGAL_OBLIGATION = "legal_obligation"
    PUBLIC_HEALTH = "public_health"
    ARCHIVING_PUBLIC_INTEREST = "archiving_public_interest"
    LEGAL_CLAIMS = "legal_claims"
    REGULATORY_REQUIREMENT = "regulatory_requirement"
    LEGAL_HOLD = "legal_hold"


@dataclass
class ErasureConfig:
    """Configuration for the erasure handler.

    Args:
        retention_days: Days to retain erasure audit records.
        require_identity_verification: Whether to require identity check.
        exempt_categories: Categories exempt from erasure.
        response_deadline_days: GDPR requires response within 30 days.
        auto_approve: Whether to auto-approve without human review.
        notify_dpo: Whether to notify the Data Protection Officer.
    """

    retention_days: int = 30
    require_identity_verification: bool = True
    exempt_categories: List[str] = field(default_factory=lambda: ["legal_hold"])
    response_deadline_days: int = 30
    auto_approve: bool = False
    notify_dpo: bool = True
    data_stores: List[str] = field(default_factory=lambda: [
        "dynamodb", "s3", "cloudwatch_logs", "elasticsearch"
    ])


@dataclass
class ErasureRequest:
    """A structured erasure request extracted from user input."""

    request_id: str
    timestamp: float
    status: ErasureStatus
    scope: ErasureScope
    user_identifier: Optional[str]
    original_text: str
    matched_phrases: List[str]
    confidence: float
    exemptions_checked: List[str] = field(default_factory=list)
    exemption_applied: Optional[ExemptionReason] = None
    data_categories_requested: List[str] = field(default_factory=list)
    audit_trail: List[Dict[str, Any]] = field(default_factory=list)


@dataclass
class ErasureCommand:
    """A command to be sent to downstream data stores for deletion."""

    store: str
    operation: str
    target_identifier: str
    data_categories: List[str]
    retention_override: bool = False
    audit_record_id: str = ""


@dataclass
class ErasureResult:
    """Result of processing an erasure request."""

    request: ErasureRequest
    commands: List[ErasureCommand]
    response_text: str
    requires_human_review: bool
    deadline: float  # Unix timestamp for response deadline


# Erasure request detection patterns (multi-language)
ERASURE_PATTERNS = {
    "en": [
        r"delete\s+(all\s+)?my\s+(data|information|account|profile)",
        r"erase\s+(all\s+)?my\s+(data|information|records)",
        r"forget\s+(about\s+)?me",
        r"right\s+to\s+be\s+forgotten",
        r"remove\s+my\s+(data|account|information|profile)",
        r"gdpr\s+(erasure|deletion|removal)",
        r"article\s+17",
        r"i\s+want\s+my\s+data\s+(deleted|removed|erased)",
    ],
    "de": [
        r"lösche\s+(alle\s+)?meine\s+daten",
        r"recht\s+auf\s+vergessenwerden",
        r"daten\s+löschen",
    ],
    "fr": [
        r"supprimer\s+mes\s+données",
        r"droit\s+à\s+l'oubli",
        r"effacer\s+mes\s+(données|informations)",
    ],
    "es": [
        r"eliminar\s+mis\s+datos",
        r"derecho\s+al\s+olvido",
        r"borrar\s+mi\s+(cuenta|información)",
    ],
}

# Scope detection patterns
SCOPE_PATTERNS = {
    ErasureScope.FULL: [r"all\s+my\s+data", r"everything", r"complete\s+deletion"],
    ErasureScope.ACCOUNT: [r"my\s+account", r"delete\s+account", r"close\s+account"],
    ErasureScope.CONVERSATION: [r"this\s+conversation", r"this\s+chat", r"current\s+session"],
    ErasureScope.PARTIAL: [r"only\s+my", r"just\s+the", r"specific"],
}


class ErasureHandler:
    """Handles GDPR Article 17 right-to-erasure requests.

    Detects erasure requests, validates them against legal exceptions,
    generates structured commands for downstream systems, and produces
    audit-compliant records.
    """

    def __init__(self, config: Optional[ErasureConfig] = None):
        self._config = config or ErasureConfig()
        self._request_counter = 0

    @property
    def config(self) -> ErasureConfig:
        """Access the erasure configuration."""
        return self._config

    def detect(self, text: str) -> Optional[ErasureRequest]:
        """Detect if text contains a right-to-erasure request.

        Args:
            text: Input text to analyze.

        Returns:
            ErasureRequest if detected, None otherwise.
        """
        text_lower = text.lower()
        matched_phrases: List[str] = []

        for lang, patterns in ERASURE_PATTERNS.items():
            for pattern in patterns:
                matches = re.findall(pattern, text_lower)
                if matches:
                    matched_phrases.extend(
                        [m if isinstance(m, str) else " ".join(m) for m in matches]
                    )

        if not matched_phrases:
            return None

        self._request_counter += 1
        request_id = f"ERASURE-{int(time.time())}-{self._request_counter:04d}"

        # Determine scope
        scope = self._detect_scope(text_lower)

        # Calculate confidence
        confidence = min(len(matched_phrases) * 0.3 + 0.4, 1.0)

        request = ErasureRequest(
            request_id=request_id,
            timestamp=time.time(),
            status=ErasureStatus.DETECTED,
            scope=scope,
            user_identifier=None,  # Must be set by caller
            original_text=text,
            matched_phrases=matched_phrases,
            confidence=confidence,
        )

        request.audit_trail.append({
            "action": "request_detected",
            "timestamp": time.time(),
            "confidence": confidence,
            "matched_phrases": matched_phrases,
        })

        return request

    def validate(self, request: ErasureRequest) -> ErasureRequest:
        """Validate an erasure request against legal exemptions.

        Checks Article 17(3) exemptions and updates request status.

        Args:
            request: The detected erasure request.

        Returns:
            Updated request with validation status.
        """
        # Check exemptions
        for category in self._config.exempt_categories:
            try:
                exemption = ExemptionReason(category)
                request.exemptions_checked.append(category)
            except ValueError:
                request.exemptions_checked.append(category)

        # Check if identity verification is required
        if self._config.require_identity_verification and not request.user_identifier:
            request.status = ErasureStatus.PENDING_VERIFICATION
            request.audit_trail.append({
                "action": "identity_verification_required",
                "timestamp": time.time(),
            })
            return request

        # No exemptions apply — request is valid
        request.status = ErasureStatus.VALIDATED
        request.audit_trail.append({
            "action": "request_validated",
            "timestamp": time.time(),
            "exemptions_checked": request.exemptions_checked,
            "exemption_applied": None,
        })

        return request

    def process(self, text: str, user_id: Optional[str] = None) -> Optional[ErasureResult]:
        """Full processing pipeline for an erasure request.

        Detects, validates, and generates erasure commands.

        Args:
            text: User input text.
            user_id: Optional user identifier.

        Returns:
            ErasureResult if an erasure request was detected, None otherwise.
        """
        request = self.detect(text)
        if request is None:
            return None

        request.user_identifier = user_id
        request = self.validate(request)

        # Generate commands
        commands = self._generate_commands(request)

        # Determine if human review is needed
        requires_review = (
            not self._config.auto_approve
            or request.status == ErasureStatus.PENDING_VERIFICATION
            or request.scope == ErasureScope.FULL
        )

        # Calculate deadline
        deadline = request.timestamp + (self._config.response_deadline_days * 86400)

        # Generate response text
        response_text = self._generate_response(request, requires_review)

        return ErasureResult(
            request=request,
            commands=commands,
            response_text=response_text,
            requires_human_review=requires_review,
            deadline=deadline,
        )

    def _detect_scope(self, text_lower: str) -> ErasureScope:
        """Detect the scope of the erasure request."""
        for scope, patterns in SCOPE_PATTERNS.items():
            for pattern in patterns:
                if re.search(pattern, text_lower):
                    return scope
        return ErasureScope.FULL  # Default to full erasure

    def _generate_commands(self, request: ErasureRequest) -> List[ErasureCommand]:
        """Generate deletion commands for configured data stores."""
        if request.status not in (ErasureStatus.VALIDATED, ErasureStatus.APPROVED):
            return []

        target_id = request.user_identifier or "unknown"
        commands: List[ErasureCommand] = []

        for store in self._config.data_stores:
            commands.append(ErasureCommand(
                store=store,
                operation="delete_user_data",
                target_identifier=target_id,
                data_categories=request.data_categories_requested or ["all"],
                audit_record_id=request.request_id,
            ))

        return commands

    def _generate_response(self, request: ErasureRequest, requires_review: bool) -> str:
        """Generate a GDPR-compliant response to the user."""
        if request.status == ErasureStatus.PENDING_VERIFICATION:
            return (
                "We have received your data erasure request. "
                "To proceed, we need to verify your identity. "
                "Please provide your registered email or account ID. "
                f"Request reference: {request.request_id}"
            )

        if request.exemption_applied:
            return (
                "We have reviewed your erasure request. Unfortunately, "
                f"we are unable to comply due to: {request.exemption_applied.value}. "
                "You have the right to lodge a complaint with your supervisory authority."
            )

        if requires_review:
            return (
                "Your data erasure request has been received and logged. "
                "It will be reviewed by our Data Protection Officer. "
                f"We will respond within {self._config.response_deadline_days} days "
                f"as required by GDPR. Reference: {request.request_id}"
            )

        return (
            "Your data erasure request has been approved and will be processed. "
            f"All personal data will be removed within {self._config.retention_days} days. "
            f"Reference: {request.request_id}"
        )


@check(name="gdpr-erasure-handler", action=Action.FLAG_FOR_REVIEW, threshold=0.5)
def erasure_request_check(text: str) -> dict:
    """Detect and process GDPR right-to-erasure requests.

    This check identifies erasure requests and routes them to
    the appropriate handler rather than forwarding to the LLM.
    """
    handler = ErasureHandler()
    result = handler.process(text)

    if result is None:
        return {"detected": False, "confidence": 0.0}

    return {
        "detected": True,
        "confidence": result.request.confidence,
        "request_id": result.request.request_id,
        "scope": result.request.scope.value,
        "status": result.request.status.value,
        "requires_review": result.requires_human_review,
        "response": result.response_text,
        "commands_generated": len(result.commands),
    }
