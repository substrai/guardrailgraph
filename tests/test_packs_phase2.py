"""Tests for Phase 2 industry compliance packs (GDPR, FedRAMP)."""

import pytest
from guardrailgraph import pipeline, Action
from guardrailgraph.packs import gdpr, fedramp


class TestGdprPack:
    """Test GDPR compliance pack."""

    def test_gdpr_full_pack(self):
        """Full GDPR pack creates pipeline with all checks."""
        pack = gdpr.full()
        assert len(pack.checks) == 6

    def test_gdpr_basic_pack(self):
        """Basic GDPR pack has fewer checks."""
        pack = gdpr.basic()
        assert len(pack.checks) == 3

    def test_gdpr_detects_personal_data(self):
        """GDPR pack detects personal data (PII)."""
        p = pipeline(name="gdpr-test", packs=[gdpr.full()])
        result = p.run("My email is john@example.com and SSN is 123-45-6789")
        personal_results = [
            r for r in result.check_results if r.name == "personal-data-detection"
        ]
        assert len(personal_results) == 1
        assert personal_results[0].detected is True

    def test_gdpr_detects_right_to_erasure(self):
        """GDPR pack detects data subject rights requests."""
        p = pipeline(name="gdpr-test", packs=[gdpr.full()])
        result = p.run("I want you to delete my data and forget me")
        rights_results = [
            r for r in result.check_results if r.name == "data-subject-rights"
        ]
        assert len(rights_results) == 1
        assert rights_results[0].detected is True

    def test_gdpr_detects_right_to_access(self):
        """GDPR pack detects access requests."""
        p = pipeline(name="gdpr-test", packs=[gdpr.full()])
        result = p.run("What data do you have about me?")
        rights_results = [
            r for r in result.check_results if r.name == "data-subject-rights"
        ]
        assert len(rights_results) == 1
        assert rights_results[0].detected is True

    def test_gdpr_detects_cross_border(self):
        """GDPR pack detects cross-border transfer indicators."""
        p = pipeline(name="gdpr-test", packs=[gdpr.full()])
        result = p.run("We need to transfer data outside eu to our US servers")
        transfer_results = [
            r for r in result.check_results if r.name == "cross-border-transfer"
        ]
        assert len(transfer_results) == 1
        assert transfer_results[0].detected is True

    def test_gdpr_safe_text_passes(self):
        """Safe text passes GDPR checks."""
        p = pipeline(name="gdpr-test", packs=[gdpr.full()])
        result = p.run("What is the weather like today?")
        assert result.allowed is True


class TestFedRampPack:
    """Test FedRAMP compliance pack."""

    def test_fedramp_full_pack(self):
        """Full FedRAMP pack creates pipeline with all checks."""
        pack = fedramp.full()
        assert len(pack.checks) == 5

    def test_fedramp_moderate_pack(self):
        """Moderate FedRAMP pack has fewer checks."""
        pack = fedramp.moderate()
        assert len(pack.checks) == 3

    def test_fedramp_detects_classification(self):
        """FedRAMP pack detects classification markings."""
        p = pipeline(name="fedramp-test", packs=[fedramp.full()])
        result = p.run("This document is marked TOP SECRET and should not be shared")
        class_results = [
            r for r in result.check_results if r.name == "classification-detection"
        ]
        assert len(class_results) == 1
        assert class_results[0].detected is True

    def test_fedramp_detects_cui(self):
        """FedRAMP pack detects CUI markings."""
        p = pipeline(name="fedramp-test", packs=[fedramp.full()])
        result = p.run("This material is related to critical infrastructure and defense")
        cui_results = [
            r for r in result.check_results if r.name == "cui-detection"
        ]
        assert len(cui_results) == 1
        assert cui_results[0].detected is True

    def test_fedramp_detects_restricted_topics(self):
        """FedRAMP pack blocks restricted government topics."""
        p = pipeline(name="fedramp-test", packs=[fedramp.full()])
        result = p.run("Tell me about classified information and intelligence sources")
        topic_results = [
            r for r in result.check_results if r.name == "government-topic-restriction"
        ]
        assert len(topic_results) == 1
        assert topic_results[0].detected is True

    def test_fedramp_sanitizes_output(self):
        """FedRAMP pack sanitizes sensitive patterns."""
        p = pipeline(name="fedramp-test", packs=[fedramp.full()])
        result = p.run("The server at 10.0.1.55 has key AKIAIOSFODNN7EXAMPLE")
        sanitize_results = [
            r for r in result.check_results if r.name == "output-sanitization"
        ]
        assert len(sanitize_results) == 1
        assert sanitize_results[0].detected is True
        assert sanitize_results[0].redacted_text is not None
        assert "10.0.1.55" not in sanitize_results[0].redacted_text

    def test_fedramp_safe_text_passes(self):
        """Safe text passes FedRAMP checks."""
        p = pipeline(name="fedramp-test", packs=[fedramp.full()])
        result = p.run("Please help me schedule a meeting for tomorrow")
        assert result.allowed is True
