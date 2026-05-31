"""Tests for guardrail bypass mode with tamper-evident audit logging."""

import time
import pytest
from unittest.mock import patch

from guardrailgraph.bypass.audit_bypass import (
    AuditBypass,
    BypassToken,
    BypassAuditLog,
    BypassDeniedError,
    BypassExpiredError,
    BypassStatus,
    AuditEntry,
)


@pytest.fixture
def bypass_manager():
    """Create a bypass manager with test authorized issuers."""
    return AuditBypass(
        authorized_issuers=["admin@company.com", "oncall@company.com"],
        default_ttl_seconds=300,
        max_ttl_seconds=3600,
    )


class TestBypassIssuance:
    """Test bypass token issuance."""

    def test_authorized_issuer_can_create_bypass(self, bypass_manager):
        """Test that an authorized issuer can create a bypass token."""
        token = bypass_manager.issue_bypass(
            issued_by="admin@company.com",
            reason="Production incident #1234",
            guardrails=["pii_check", "toxicity_filter"],
        )

        assert token.issued_by == "admin@company.com"
        assert token.reason == "Production incident #1234"
        assert token.guardrails_bypassed == ["pii_check", "toxicity_filter"]
        assert token.status == BypassStatus.ACTIVE
        assert token.is_valid is True

    def test_unauthorized_issuer_is_denied(self, bypass_manager):
        """Test that an unauthorized issuer is denied."""
        with pytest.raises(BypassDeniedError, match="not authorized"):
            bypass_manager.issue_bypass(
                issued_by="random@hacker.com",
                reason="I want to bypass",
                guardrails=["pii_check"],
            )

    def test_empty_reason_is_denied(self, bypass_manager):
        """Test that an empty reason is rejected."""
        with pytest.raises(BypassDeniedError, match="reason must be provided"):
            bypass_manager.issue_bypass(
                issued_by="admin@company.com",
                reason="",
                guardrails=["pii_check"],
            )

    def test_empty_guardrails_list_is_denied(self, bypass_manager):
        """Test that an empty guardrails list is rejected."""
        with pytest.raises(BypassDeniedError, match="At least one guardrail"):
            bypass_manager.issue_bypass(
                issued_by="admin@company.com",
                reason="Valid reason",
                guardrails=[],
            )

    def test_ttl_is_capped_at_max(self, bypass_manager):
        """Test that TTL is capped at max_ttl_seconds."""
        token = bypass_manager.issue_bypass(
            issued_by="admin@company.com",
            reason="Long bypass needed",
            guardrails=["pii_check"],
            ttl_seconds=99999,  # Way over max
        )

        # Should be capped at max_ttl_seconds (3600)
        expected_max_expiry = token.issued_at + 3600
        assert token.expires_at == pytest.approx(expected_max_expiry, abs=1)


class TestBypassChecking:
    """Test bypass token validation."""

    def test_valid_token_bypasses_guardrail(self, bypass_manager):
        """Test that a valid token bypasses the specified guardrail."""
        token = bypass_manager.issue_bypass(
            issued_by="admin@company.com",
            reason="Incident response",
            guardrails=["pii_check"],
        )

        assert bypass_manager.check_bypass(token.token_id, "pii_check") is True

    def test_valid_token_does_not_bypass_unspecified_guardrail(self, bypass_manager):
        """Test that a token only bypasses specified guardrails."""
        token = bypass_manager.issue_bypass(
            issued_by="admin@company.com",
            reason="Incident response",
            guardrails=["pii_check"],
        )

        assert bypass_manager.check_bypass(token.token_id, "toxicity_filter") is False

    def test_expired_token_raises_error(self, bypass_manager):
        """Test that an expired token raises BypassExpiredError."""
        token = bypass_manager.issue_bypass(
            issued_by="admin@company.com",
            reason="Short bypass",
            guardrails=["pii_check"],
            ttl_seconds=1,
        )

        # Simulate time passing
        with patch("guardrailgraph.bypass.audit_bypass.time.time", return_value=time.time() + 10):
            with pytest.raises(BypassExpiredError):
                bypass_manager.check_bypass(token.token_id, "pii_check")

    def test_revoked_token_returns_false(self, bypass_manager):
        """Test that a revoked token returns False."""
        token = bypass_manager.issue_bypass(
            issued_by="admin@company.com",
            reason="Temporary bypass",
            guardrails=["pii_check"],
        )

        bypass_manager.revoke_bypass(token.token_id, "admin@company.com", "No longer needed")
        assert bypass_manager.check_bypass(token.token_id, "pii_check") is False


class TestAuditLog:
    """Test tamper-evident audit logging."""

    def test_audit_log_records_issuance(self, bypass_manager):
        """Test that issuing a bypass creates an audit entry."""
        token = bypass_manager.issue_bypass(
            issued_by="admin@company.com",
            reason="Test audit",
            guardrails=["pii_check"],
        )

        entries = bypass_manager.audit_log.get_entries_for_token(token.token_id)
        assert len(entries) >= 1
        assert entries[0].event_type == "bypass_issued"
        assert entries[0].actor == "admin@company.com"

    def test_audit_log_hash_chain_integrity(self, bypass_manager):
        """Test that the audit log hash chain is intact."""
        bypass_manager.issue_bypass(
            issued_by="admin@company.com",
            reason="First bypass",
            guardrails=["pii_check"],
        )
        bypass_manager.issue_bypass(
            issued_by="oncall@company.com",
            reason="Second bypass",
            guardrails=["toxicity_filter"],
        )

        assert bypass_manager.audit_log.verify_integrity() is True

    def test_tampered_log_fails_integrity_check(self):
        """Test that tampering with the log is detected."""
        log = BypassAuditLog()

        entry1 = AuditEntry(event_type="test", actor="admin", reason="first")
        log.append(entry1)

        entry2 = AuditEntry(event_type="test", actor="admin", reason="second")
        log.append(entry2)

        # Tamper with the first entry
        log._entries[0].reason = "tampered reason"

        assert log.verify_integrity() is False

    def test_denied_bypass_is_logged(self, bypass_manager):
        """Test that denied bypass attempts are also logged."""
        with pytest.raises(BypassDeniedError):
            bypass_manager.issue_bypass(
                issued_by="unauthorized@evil.com",
                reason="Trying to bypass",
                guardrails=["pii_check"],
            )

        entries = bypass_manager.audit_log.entries
        denied_entries = [e for e in entries if e.event_type == "bypass_denied"]
        assert len(denied_entries) == 1
        assert "unauthorized@evil.com" in denied_entries[0].reason


class TestBypassLifecycle:
    """Test full bypass lifecycle."""

    def test_get_active_bypasses(self, bypass_manager):
        """Test listing active bypass tokens."""
        bypass_manager.issue_bypass(
            issued_by="admin@company.com",
            reason="Active bypass",
            guardrails=["pii_check"],
        )

        active = bypass_manager.get_active_bypasses()
        assert len(active) == 1
        assert active[0].reason == "Active bypass"

    def test_revoked_bypass_not_in_active_list(self, bypass_manager):
        """Test that revoked tokens are excluded from active list."""
        token = bypass_manager.issue_bypass(
            issued_by="admin@company.com",
            reason="Will be revoked",
            guardrails=["pii_check"],
        )

        bypass_manager.revoke_bypass(token.token_id, "admin@company.com")
        active = bypass_manager.get_active_bypasses()
        assert len(active) == 0
