"""Emergency guardrail bypass with tamper-evident audit logging.

Provides a controlled mechanism to bypass guardrails in emergency situations
while maintaining a cryptographically verifiable audit trail.

Features:
- Token-based authentication for bypass authorization
- Auto-expiry of bypass windows (configurable duration)
- Hash-chain audit log for tamper evidence
- Full reason tracking and metadata capture
"""

import hashlib
import json
import time
import uuid
import logging
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional

logger = logging.getLogger("guardrailgraph.bypass")


class BypassDeniedError(Exception):
    """Raised when a bypass attempt is denied."""
    pass


class BypassExpiredError(Exception):
    """Raised when a bypass token has expired."""
    pass


class BypassStatus(str, Enum):
    """Status of a bypass token."""
    ACTIVE = "active"
    EXPIRED = "expired"
    REVOKED = "revoked"


@dataclass
class BypassToken:
    """Represents an authorized bypass token.

    Attributes:
        token_id: Unique identifier for this bypass token.
        issued_by: Identity of the person/system that issued the token.
        reason: Human-readable reason for the bypass.
        issued_at: Unix timestamp when the token was issued.
        expires_at: Unix timestamp when the token expires.
        guardrails_bypassed: List of guardrail IDs being bypassed.
        status: Current status of the token.
    """
    token_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    issued_by: str = ""
    reason: str = ""
    issued_at: float = field(default_factory=time.time)
    expires_at: float = 0.0
    guardrails_bypassed: list = field(default_factory=list)
    status: BypassStatus = BypassStatus.ACTIVE

    @property
    def is_expired(self) -> bool:
        """Check if the token has expired."""
        return time.time() > self.expires_at

    @property
    def is_valid(self) -> bool:
        """Check if the token is currently valid."""
        return self.status == BypassStatus.ACTIVE and not self.is_expired

    def to_dict(self) -> dict:
        """Serialize token to dictionary."""
        return {
            "token_id": self.token_id,
            "issued_by": self.issued_by,
            "reason": self.reason,
            "issued_at": self.issued_at,
            "expires_at": self.expires_at,
            "guardrails_bypassed": self.guardrails_bypassed,
            "status": self.status.value,
        }


@dataclass
class AuditEntry:
    """A single entry in the tamper-evident audit log.

    Each entry contains a hash of the previous entry, forming a chain
    that makes tampering detectable.
    """
    entry_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: float = field(default_factory=time.time)
    event_type: str = ""
    token_id: str = ""
    actor: str = ""
    reason: str = ""
    guardrails_bypassed: list = field(default_factory=list)
    metadata: dict = field(default_factory=dict)
    previous_hash: str = ""
    entry_hash: str = ""

    def compute_hash(self) -> str:
        """Compute the hash for this entry based on its content."""
        content = json.dumps({
            "entry_id": self.entry_id,
            "timestamp": self.timestamp,
            "event_type": self.event_type,
            "token_id": self.token_id,
            "actor": self.actor,
            "reason": self.reason,
            "guardrails_bypassed": self.guardrails_bypassed,
            "metadata": self.metadata,
            "previous_hash": self.previous_hash,
        }, sort_keys=True)
        return hashlib.sha256(content.encode()).hexdigest()

    def to_dict(self) -> dict:
        """Serialize entry to dictionary."""
        return {
            "entry_id": self.entry_id,
            "timestamp": self.timestamp,
            "event_type": self.event_type,
            "token_id": self.token_id,
            "actor": self.actor,
            "reason": self.reason,
            "guardrails_bypassed": self.guardrails_bypassed,
            "metadata": self.metadata,
            "previous_hash": self.previous_hash,
            "entry_hash": self.entry_hash,
        }


class BypassAuditLog:
    """Tamper-evident audit log using hash chains.

    Each log entry contains the hash of the previous entry, creating
    a chain that makes any modification detectable.
    """

    def __init__(self):
        self._entries: list[AuditEntry] = []
        self._genesis_hash = hashlib.sha256(b"genesis").hexdigest()

    @property
    def entries(self) -> list[AuditEntry]:
        """Return all audit entries."""
        return list(self._entries)

    @property
    def last_hash(self) -> str:
        """Return the hash of the last entry, or genesis hash if empty."""
        if not self._entries:
            return self._genesis_hash
        return self._entries[-1].entry_hash

    def append(self, entry: AuditEntry) -> AuditEntry:
        """Append an entry to the audit log with hash chain linking."""
        entry.previous_hash = self.last_hash
        entry.entry_hash = entry.compute_hash()
        self._entries.append(entry)
        return entry

    def verify_integrity(self) -> bool:
        """Verify the entire hash chain is intact.

        Returns True if the chain is valid, False if tampering is detected.
        """
        if not self._entries:
            return True

        # Verify first entry links to genesis
        if self._entries[0].previous_hash != self._genesis_hash:
            return False

        for i, entry in enumerate(self._entries):
            # Verify entry hash matches computed hash
            if entry.entry_hash != entry.compute_hash():
                return False

            # Verify chain linkage (skip first entry)
            if i > 0 and entry.previous_hash != self._entries[i - 1].entry_hash:
                return False

        return True

    def get_entries_for_token(self, token_id: str) -> list[AuditEntry]:
        """Get all audit entries related to a specific token."""
        return [e for e in self._entries if e.token_id == token_id]


class AuditBypass:
    """Emergency guardrail bypass manager with tamper-evident audit logging.

    Provides controlled bypass of guardrails with:
    - Token-based authorization
    - Configurable auto-expiry
    - Full audit trail with hash chain integrity
    - Reason tracking for compliance

    Args:
        authorized_issuers: List of identities allowed to issue bypass tokens.
        default_ttl_seconds: Default time-to-live for bypass tokens (default: 300s / 5 min).
        max_ttl_seconds: Maximum allowed TTL for any bypass token (default: 3600s / 1 hour).
    """

    def __init__(
        self,
        authorized_issuers: list[str] | None = None,
        default_ttl_seconds: int = 300,
        max_ttl_seconds: int = 3600,
    ):
        self.authorized_issuers = authorized_issuers or []
        self.default_ttl_seconds = default_ttl_seconds
        self.max_ttl_seconds = max_ttl_seconds
        self._active_tokens: dict[str, BypassToken] = {}
        self.audit_log = BypassAuditLog()

    def issue_bypass(
        self,
        issued_by: str,
        reason: str,
        guardrails: list[str],
        ttl_seconds: int | None = None,
        metadata: dict | None = None,
    ) -> BypassToken:
        """Issue a new bypass token.

        Args:
            issued_by: Identity of the issuer (must be in authorized_issuers).
            reason: Human-readable reason for the bypass.
            guardrails: List of guardrail IDs to bypass.
            ttl_seconds: Custom TTL (capped at max_ttl_seconds).
            metadata: Additional metadata to record in audit log.

        Returns:
            A BypassToken if authorized.

        Raises:
            BypassDeniedError: If the issuer is not authorized.
        """
        if self.authorized_issuers and issued_by not in self.authorized_issuers:
            self._log_event(
                event_type="bypass_denied",
                token_id="",
                actor=issued_by,
                reason=f"Unauthorized issuer attempted bypass: {reason}",
                guardrails=guardrails,
                metadata=metadata or {},
            )
            raise BypassDeniedError(
                f"Issuer '{issued_by}' is not authorized to issue bypass tokens"
            )

        if not reason or not reason.strip():
            raise BypassDeniedError("A reason must be provided for bypass")

        if not guardrails:
            raise BypassDeniedError("At least one guardrail must be specified")

        # Calculate TTL (capped at max)
        effective_ttl = min(ttl_seconds or self.default_ttl_seconds, self.max_ttl_seconds)
        now = time.time()

        token = BypassToken(
            issued_by=issued_by,
            reason=reason,
            issued_at=now,
            expires_at=now + effective_ttl,
            guardrails_bypassed=guardrails,
            status=BypassStatus.ACTIVE,
        )

        self._active_tokens[token.token_id] = token

        self._log_event(
            event_type="bypass_issued",
            token_id=token.token_id,
            actor=issued_by,
            reason=reason,
            guardrails=guardrails,
            metadata=metadata or {},
        )

        logger.warning(
            f"Bypass token issued: {token.token_id} by {issued_by} "
            f"for guardrails {guardrails} (expires in {effective_ttl}s)"
        )

        return token

    def check_bypass(self, token_id: str, guardrail_id: str) -> bool:
        """Check if a guardrail is currently bypassed by a valid token.

        Args:
            token_id: The bypass token ID to check.
            guardrail_id: The guardrail ID to check bypass for.

        Returns:
            True if the guardrail is bypassed, False otherwise.

        Raises:
            BypassExpiredError: If the token has expired.
        """
        token = self._active_tokens.get(token_id)
        if not token:
            return False

        if token.is_expired:
            token.status = BypassStatus.EXPIRED
            self._log_event(
                event_type="bypass_expired",
                token_id=token_id,
                actor="system",
                reason="Token expired during check",
                guardrails=token.guardrails_bypassed,
            )
            raise BypassExpiredError(f"Bypass token {token_id} has expired")

        if token.status != BypassStatus.ACTIVE:
            return False

        is_bypassed = guardrail_id in token.guardrails_bypassed

        self._log_event(
            event_type="bypass_checked",
            token_id=token_id,
            actor="system",
            reason=f"Checked guardrail {guardrail_id}: {'bypassed' if is_bypassed else 'not bypassed'}",
            guardrails=[guardrail_id],
        )

        return is_bypassed

    def revoke_bypass(self, token_id: str, revoked_by: str, reason: str = "") -> None:
        """Revoke an active bypass token.

        Args:
            token_id: The token to revoke.
            revoked_by: Identity of the person revoking.
            reason: Optional reason for revocation.
        """
        token = self._active_tokens.get(token_id)
        if not token:
            return

        token.status = BypassStatus.REVOKED

        self._log_event(
            event_type="bypass_revoked",
            token_id=token_id,
            actor=revoked_by,
            reason=reason or "Manual revocation",
            guardrails=token.guardrails_bypassed,
        )

        logger.info(f"Bypass token revoked: {token_id} by {revoked_by}")

    def get_active_bypasses(self) -> list[BypassToken]:
        """Return all currently active (non-expired, non-revoked) bypass tokens."""
        active = []
        for token in self._active_tokens.values():
            if token.is_expired and token.status == BypassStatus.ACTIVE:
                token.status = BypassStatus.EXPIRED
            if token.is_valid:
                active.append(token)
        return active

    def _log_event(
        self,
        event_type: str,
        token_id: str,
        actor: str,
        reason: str,
        guardrails: list[str],
        metadata: dict | None = None,
    ) -> None:
        """Append an event to the tamper-evident audit log."""
        entry = AuditEntry(
            event_type=event_type,
            token_id=token_id,
            actor=actor,
            reason=reason,
            guardrails_bypassed=guardrails,
            metadata=metadata or {},
        )
        self.audit_log.append(entry)
