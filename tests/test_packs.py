"""Tests for industry compliance packs."""

import pytest
from guardrailgraph import pipeline, Action
from guardrailgraph.packs import hipaa, financial


class TestHipaaPack:
    """Test HIPAA compliance pack."""

    def test_hipaa_full_pack(self):
        """Full HIPAA pack creates pipeline with all checks."""
        pack = hipaa.full()
        assert len(pack.checks) == 4

    def test_hipaa_basic_pack(self):
        """Basic HIPAA pack has fewer checks."""
        pack = hipaa.basic()
        assert len(pack.checks) == 2

    def test_hipaa_detects_phi(self):
        """HIPAA pack detects PHI."""
        p = pipeline(name="hipaa-test", packs=[hipaa.full()])
        result = p.run("Patient SSN: 123-45-6789")
        # Should detect PII/PHI
        phi_results = [r for r in result.check_results if r.name == "phi-detection"]
        assert len(phi_results) == 1
        assert phi_results[0].detected is True

    def test_hipaa_detects_medical_claims(self):
        """HIPAA pack flags medical claims."""
        p = pipeline(name="hipaa-test", packs=[hipaa.full()])
        result = p.run("You have diabetes and I recommend taking insulin")
        medical_results = [
            r for r in result.check_results
            if r.name == "medical-claim-detection"
        ]
        assert len(medical_results) == 1
        assert medical_results[0].detected is True

    def test_hipaa_safe_text_passes(self):
        """Safe text passes HIPAA checks."""
        p = pipeline(name="hipaa-test", packs=[hipaa.full()])
        result = p.run("How can I help you today?")
        # Should not be blocked (audit log always detects but doesn't block)
        assert result.allowed is True


class TestFinancialPack:
    """Test financial/SOX compliance pack."""

    def test_sox_pack(self):
        """SOX pack creates pipeline with checks."""
        pack = financial.sox()
        assert len(pack.checks) == 3

    def test_sox_detects_financial_advice(self):
        """SOX pack detects financial advice."""
        p = pipeline(name="sox-test", packs=[financial.sox()])
        result = p.run("You should invest in this stock, guaranteed returns")
        advice_results = [
            r for r in result.check_results
            if r.name == "financial-advice-detection"
        ]
        assert len(advice_results) == 1
        assert advice_results[0].detected is True

    def test_sox_detects_insider_info(self):
        """SOX pack detects insider information."""
        p = pipeline(name="sox-test", packs=[financial.sox()])
        result = p.run("I have insider information about the merger talks")
        insider_results = [
            r for r in result.check_results
            if r.name == "insider-info-detection"
        ]
        assert len(insider_results) == 1
        assert insider_results[0].detected is True

    def test_sox_safe_text_passes(self):
        """Safe text passes SOX checks."""
        p = pipeline(name="sox-test", packs=[financial.sox()])
        result = p.run("What are your business hours?")
        assert result.allowed is True
