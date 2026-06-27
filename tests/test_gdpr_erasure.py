"""Tests for GDPR Right-to-Erasure handler."""

from __future__ import annotations

import pytest

from guardrailgraph.packs.gdpr_erasure import (
    ErasureConfig,
    ErasureHandler,
    ErasureRequest,
    ErasureResult,
    ErasureScope,
    ErasureStatus,
    ExemptionReason,
    erasure_request_check,
)


class TestErasureDetection:
    """Test erasure request detection from user input."""

    def test_detect_simple_delete_request(self):
        handler = ErasureHandler()
        request = handler.detect("Please delete all my data")
        assert request is not None
        assert request.status == ErasureStatus.DETECTED
        assert request.confidence > 0.5

    def test_detect_right_to_be_forgotten(self):
        handler = ErasureHandler()
        request = handler.detect("I invoke my right to be forgotten under GDPR")
        assert request is not None
        assert len(request.matched_phrases) > 0

    def test_detect_article_17_reference(self):
        handler = ErasureHandler()
        request = handler.detect("Per Article 17, erase my information")
        assert request is not None

    def test_detect_german_erasure_request(self):
        handler = ErasureHandler()
        request = handler.detect("Bitte lösche alle meine Daten")
        assert request is not None

    def test_detect_french_erasure_request(self):
        handler = ErasureHandler()
        request = handler.detect("Je demande le droit à l'oubli")
        assert request is not None

    def test_no_detection_on_normal_text(self):
        handler = ErasureHandler()
        request = handler.detect("What is the weather like today?")
        assert request is None

    def test_no_detection_on_unrelated_delete(self):
        handler = ErasureHandler()
        request = handler.detect("Delete the second paragraph from the document")
        assert request is None

    def test_request_id_generated(self):
        handler = ErasureHandler()
        request = handler.detect("Delete my data now")
        assert request is not None
        assert request.request_id.startswith("ERASURE-")

    def test_audit_trail_created(self):
        handler = ErasureHandler()
        request = handler.detect("Forget me please")
        assert request is not None
        assert len(request.audit_trail) == 1
        assert request.audit_trail[0]["action"] == "request_detected"


class TestErasureScopeDetection:
    """Test scope detection for erasure requests."""

    def test_full_scope_all_data(self):
        handler = ErasureHandler()
        request = handler.detect("Delete all my data completely")
        assert request is not None
        assert request.scope == ErasureScope.FULL

    def test_account_scope(self):
        handler = ErasureHandler()
        request = handler.detect("Delete my account permanently")
        assert request is not None
        assert request.scope == ErasureScope.ACCOUNT

    def test_conversation_scope(self):
        handler = ErasureHandler()
        request = handler.detect("Erase my data from this conversation")
        assert request is not None
        assert request.scope == ErasureScope.CONVERSATION

    def test_default_to_full_scope(self):
        handler = ErasureHandler()
        request = handler.detect("Right to be forgotten please")
        assert request is not None
        assert request.scope == ErasureScope.FULL


class TestErasureValidation:
    """Test request validation logic."""

    def test_validation_requires_identity(self):
        config = ErasureConfig(require_identity_verification=True)
        handler = ErasureHandler(config=config)
        request = handler.detect("Delete all my data")
        assert request is not None

        validated = handler.validate(request)
        assert validated.status == ErasureStatus.PENDING_VERIFICATION

    def test_validation_passes_with_user_id(self):
        config = ErasureConfig(require_identity_verification=True)
        handler = ErasureHandler(config=config)
        request = handler.detect("Delete all my data")
        assert request is not None
        request.user_identifier = "user-123"

        validated = handler.validate(request)
        assert validated.status == ErasureStatus.VALIDATED

    def test_validation_without_identity_requirement(self):
        config = ErasureConfig(require_identity_verification=False)
        handler = ErasureHandler(config=config)
        request = handler.detect("Delete all my data")
        assert request is not None

        validated = handler.validate(request)
        assert validated.status == ErasureStatus.VALIDATED

    def test_validation_records_audit_trail(self):
        config = ErasureConfig(require_identity_verification=False)
        handler = ErasureHandler(config=config)
        request = handler.detect("Delete my data")
        assert request is not None

        validated = handler.validate(request)
        assert len(validated.audit_trail) == 2
        assert validated.audit_trail[1]["action"] == "request_validated"


class TestErasureProcessing:
    """Test full processing pipeline."""

    def test_full_pipeline_with_user_id(self):
        config = ErasureConfig(require_identity_verification=True)
        handler = ErasureHandler(config=config)
        result = handler.process("Please delete all my data", user_id="user-456")
        assert result is not None
        assert result.request.status == ErasureStatus.VALIDATED
        assert len(result.commands) > 0

    def test_commands_generated_for_all_stores(self):
        config = ErasureConfig(
            data_stores=["dynamodb", "s3", "elasticsearch"],
            require_identity_verification=False,
        )
        handler = ErasureHandler(config=config)
        result = handler.process("Erase my information")
        assert result is not None
        assert len(result.commands) == 3
        stores = [cmd.store for cmd in result.commands]
        assert "dynamodb" in stores
        assert "s3" in stores

    def test_deadline_set_correctly(self):
        config = ErasureConfig(response_deadline_days=30)
        handler = ErasureHandler(config=config)
        result = handler.process("Delete my data", user_id="u1")
        assert result is not None
        # Deadline should be ~30 days from now
        assert result.deadline > result.request.timestamp
        expected_delta = 30 * 86400
        actual_delta = result.deadline - result.request.timestamp
        assert abs(actual_delta - expected_delta) < 1.0

    def test_requires_human_review_for_full_scope(self):
        config = ErasureConfig(auto_approve=False)
        handler = ErasureHandler(config=config)
        result = handler.process("Delete all my data", user_id="u1")
        assert result is not None
        assert result.requires_human_review is True

    def test_no_result_for_normal_text(self):
        handler = ErasureHandler()
        result = handler.process("Tell me about machine learning")
        assert result is None

    def test_response_text_for_pending_verification(self):
        config = ErasureConfig(require_identity_verification=True)
        handler = ErasureHandler(config=config)
        result = handler.process("Delete my data")  # No user_id
        assert result is not None
        assert "verify your identity" in result.response_text

    def test_response_text_for_review_required(self):
        config = ErasureConfig(
            require_identity_verification=False,
            auto_approve=False,
        )
        handler = ErasureHandler(config=config)
        result = handler.process("Erase my information")
        assert result is not None
        assert "Data Protection Officer" in result.response_text


class TestErasureCheckIntegration:
    """Test the @check-decorated function."""

    def test_check_detects_erasure(self):
        result = erasure_request_check("Please delete all my data")
        assert result["detected"] is True
        assert result["confidence"] > 0.5
        assert "request_id" in result

    def test_check_passes_normal_text(self):
        result = erasure_request_check("What is the capital of France?")
        assert result["detected"] is False
        assert result["confidence"] == 0.0

    def test_check_returns_scope(self):
        result = erasure_request_check("Delete my account permanently")
        assert result["detected"] is True
        assert result["scope"] == "account"
