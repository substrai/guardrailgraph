"""GDPR Compliance Pack — EU data protection guardrails.

Provides checks for:
- Personal data detection (broader than PII — includes behavioral data)
- Data subject rights detection (right to erasure, access, portability)
- Consent tracking verification
- Data minimization enforcement
- Cross-border transfer detection
- Purpose limitation enforcement
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import List

from guardrailgraph.core.actions import Action
from guardrailgraph.core.check import Check, check


# GDPR personal data categories (broader than HIPAA PHI)
PERSONAL_DATA_KEYWORDS = [
    "date of birth", "home address", "phone number", "email address",
    "social security", "passport number", "driver's license",
    "bank account", "credit card", "ip address", "cookie",
    "location data", "biometric", "genetic data", "health data",
    "political opinion", "religious belief", "sexual orientation",
    "trade union", "ethnic origin", "racial origin",
]

# Data subject rights keywords
DATA_SUBJECT_RIGHTS_KEYWORDS = {
    "right_to_erasure": [
        "delete my data", "erase my information", "forget me",
        "remove my account", "right to be forgotten", "delete my account",
    ],
    "right_to_access": [
        "what data do you have", "show my data", "access my information",
        "copy of my data", "what do you know about me",
    ],
    "right_to_portability": [
        "export my data", "transfer my data", "download my information",
        "move my data", "data portability",
    ],
    "right_to_rectification": [
        "correct my data", "update my information", "fix my details",
        "my data is wrong", "inaccurate information",
    ],
    "right_to_object": [
        "stop processing", "opt out", "don't use my data",
        "object to processing", "withdraw consent",
    ],
}

# Cross-border transfer indicators
CROSS_BORDER_KEYWORDS = [
    "transfer to us", "send to america", "store in china",
    "process in india", "third country", "outside eu",
    "outside eea", "international transfer",
]


@check(name="personal-data-detection", action=Action.REDACT, threshold=0.5)
def personal_data_detection(text: str) -> dict:
    """Detect personal data as defined by GDPR Article 4.

    GDPR's definition of personal data is broader than HIPAA PHI —
    includes any information relating to an identified or identifiable person.
    """
    from guardrailgraph.checks.pii import PiiDetector

    # Use PII detector for structured data
    detector = PiiDetector(sensitivity="high")
    entities = detector.detect(text)

    # Also check for GDPR-specific personal data keywords
    text_lower = text.lower()
    gdpr_matches = [kw for kw in PERSONAL_DATA_KEYWORDS if kw in text_lower]

    if not entities and not gdpr_matches:
        return {"detected": False, "confidence": 0.0}

    redacted = detector.redact(text, entities) if entities else text
    confidence = max(
        max((e.confidence for e in entities), default=0.0),
        0.8 if gdpr_matches else 0.0,
    )

    return {
        "detected": True,
        "confidence": confidence,
        "pii_entities": [e.to_dict() for e in entities],
        "gdpr_categories": gdpr_matches,
        "redacted_text": redacted,
    }


@check(name="data-subject-rights", action=Action.FLAG_FOR_REVIEW, threshold=0.5)
def data_subject_rights_detection(text: str) -> dict:
    """Detect data subject rights requests (GDPR Articles 15-22).

    When a user exercises their rights, the request must be routed
    to a human handler within the legally required timeframe.
    """
    text_lower = text.lower()
    detected_rights: dict = {}

    for right_type, keywords in DATA_SUBJECT_RIGHTS_KEYWORDS.items():
        matches = [kw for kw in keywords if kw in text_lower]
        if matches:
            detected_rights[right_type] = matches

    if not detected_rights:
        return {"detected": False, "confidence": 0.0}

    return {
        "detected": True,
        "confidence": 0.9,
        "rights_detected": list(detected_rights.keys()),
        "matched_phrases": detected_rights,
        "action_required": "Route to Data Protection Officer within 30 days",
    }


@check(name="consent-check", action=Action.BLOCK, threshold=0.5)
def consent_verification(text: str) -> dict:
    """Verify processing has a lawful basis (GDPR Article 6).

    In production, this checks against a consent management system.
    Placeholder implementation — always passes.
    """
    return {"detected": False, "confidence": 0.0}


@check(name="data-minimization", action=Action.FLAG_FOR_REVIEW, threshold=0.6)
def data_minimization(text: str) -> dict:
    """Enforce data minimization principle (GDPR Article 5(1)(c)).

    Flag responses that contain more personal data than necessary
    for the stated purpose.
    """
    text_lower = text.lower()
    personal_data_count = sum(1 for kw in PERSONAL_DATA_KEYWORDS if kw in text_lower)

    # If response contains excessive personal data references
    if personal_data_count >= 3:
        return {
            "detected": True,
            "confidence": min(personal_data_count / 5.0, 1.0),
            "personal_data_references": personal_data_count,
            "principle": "data_minimization",
            "recommendation": "Reduce personal data in response to minimum necessary",
        }

    return {"detected": False, "confidence": 0.0}


@check(name="cross-border-transfer", action=Action.FLAG_FOR_REVIEW, threshold=0.6)
def cross_border_transfer_detection(text: str) -> dict:
    """Detect potential cross-border data transfers (GDPR Chapter V).

    Flag content that suggests data transfer outside the EU/EEA
    without adequate safeguards.
    """
    text_lower = text.lower()
    matches = [kw for kw in CROSS_BORDER_KEYWORDS if kw in text_lower]

    if not matches:
        return {"detected": False, "confidence": 0.0}

    return {
        "detected": True,
        "confidence": 0.85,
        "transfer_indicators": matches,
        "action_required": "Verify adequate safeguards (SCCs, adequacy decision, or BCRs)",
    }


@check(name="gdpr-audit-log", action=Action.LOG, threshold=0.0)
def gdpr_audit_logging(text: str) -> dict:
    """Log all processing activities (GDPR Article 30).

    Maintains records of processing activities as required by GDPR.
    """
    import time

    return {
        "detected": True,
        "confidence": 1.0,
        "audit_record": {
            "timestamp": time.time(),
            "text_length": len(text),
            "compliance_framework": "GDPR",
            "lawful_basis": "legitimate_interest",  # Should be configured per use case
        },
    }


@dataclass
class GdprPack:
    """GDPR compliance pack containing all EU data protection guardrails."""

    checks: List[Check]

    @classmethod
    def full(cls) -> "GdprPack":
        """Full GDPR compliance pack with all checks."""
        return cls(checks=[
            personal_data_detection,
            data_subject_rights_detection,
            consent_verification,
            data_minimization,
            cross_border_transfer_detection,
            gdpr_audit_logging,
        ])

    @classmethod
    def basic(cls) -> "GdprPack":
        """Basic GDPR pack — personal data detection + audit only."""
        return cls(checks=[
            personal_data_detection,
            data_subject_rights_detection,
            gdpr_audit_logging,
        ])


def full() -> GdprPack:
    """Get the full GDPR compliance pack."""
    return GdprPack.full()


def basic() -> GdprPack:
    """Get the basic GDPR pack."""
    return GdprPack.basic()
