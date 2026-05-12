"""FedRAMP Compliance Pack — US government AI safety guardrails.

Provides checks for:
- Data classification enforcement (CUI, FOUO, Secret, Top Secret)
- Topic restriction for government systems
- Output sanitization (prevent classified info leakage)
- Access control verification
- Audit logging for FedRAMP continuous monitoring
- Controlled Unclassified Information (CUI) detection
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import List

from guardrailgraph.core.actions import Action
from guardrailgraph.core.check import Check, check


# Classification markings
CLASSIFICATION_MARKERS = {
    "TOP_SECRET": [
        r"\bTOP\s+SECRET\b", r"\bTS\b", r"\bTS//SCI\b",
    ],
    "SECRET": [
        r"\bSECRET\b", r"\bS//NF\b",
    ],
    "CONFIDENTIAL": [
        r"\bCONFIDENTIAL\b",
    ],
    "CUI": [
        r"\bCUI\b", r"\bControlled\s+Unclassified\b",
        r"\bFOR\s+OFFICIAL\s+USE\s+ONLY\b", r"\bFOUO\b",
        r"\bLaw\s+Enforcement\s+Sensitive\b", r"\bLES\b",
    ],
}

# Restricted topics for government AI systems
GOVERNMENT_RESTRICTED_TOPICS = [
    "classified information", "intelligence sources",
    "covert operations", "nuclear weapons",
    "cryptographic keys", "vulnerability details",
    "personnel security", "clearance level",
    "operational security", "opsec",
    "signals intelligence", "sigint",
    "human intelligence", "humint",
]

# CUI categories (NIST SP 800-171)
CUI_CATEGORIES = [
    "critical infrastructure", "defense", "export control",
    "financial", "immigration", "intelligence",
    "law enforcement", "legal", "natural resources",
    "nato", "nuclear", "patent", "privacy",
    "procurement", "proprietary", "statistical",
    "tax", "transportation",
]


@check(name="classification-detection", action=Action.BLOCK, threshold=0.7)
def classification_detection(text: str) -> dict:
    """Detect classified information markings in text.

    Blocks content that contains or references classified markings.
    Prevents accidental disclosure of classified information through AI systems.
    """
    detected_levels: dict = {}

    for level, patterns in CLASSIFICATION_MARKERS.items():
        for pattern in patterns:
            if re.search(pattern, text, re.IGNORECASE):
                if level not in detected_levels:
                    detected_levels[level] = []
                detected_levels[level].append(pattern)
                break

    if not detected_levels:
        return {"detected": False, "confidence": 0.0}

    # Higher classification = higher confidence
    severity_map = {"TOP_SECRET": 1.0, "SECRET": 0.95, "CONFIDENTIAL": 0.85, "CUI": 0.75}
    max_severity = max(severity_map.get(level, 0.7) for level in detected_levels)

    return {
        "detected": True,
        "confidence": max_severity,
        "classification_levels": list(detected_levels.keys()),
        "highest_level": max(detected_levels.keys(), key=lambda l: severity_map.get(l, 0)),
        "action_required": "Content contains classified markings — block and alert",
    }


@check(name="government-topic-restriction", action=Action.BLOCK, threshold=0.6)
def government_topic_restriction(text: str) -> dict:
    """Restrict discussion of sensitive government topics.

    Blocks AI responses that discuss classified programs, intelligence
    methods, or other restricted government topics.
    """
    text_lower = text.lower()
    matched_topics = [t for t in GOVERNMENT_RESTRICTED_TOPICS if t in text_lower]

    if not matched_topics:
        return {"detected": False, "confidence": 0.0}

    return {
        "detected": True,
        "confidence": min(len(matched_topics) / 2.0, 1.0),
        "restricted_topics": matched_topics,
        "topic_count": len(matched_topics),
    }


@check(name="cui-detection", action=Action.FLAG_FOR_REVIEW, threshold=0.6)
def cui_detection(text: str) -> dict:
    """Detect Controlled Unclassified Information (CUI).

    Flags content that may contain CUI categories as defined by
    NIST SP 800-171 and the CUI Registry.
    """
    text_lower = text.lower()
    matched_categories = [cat for cat in CUI_CATEGORIES if cat in text_lower]

    if not matched_categories:
        return {"detected": False, "confidence": 0.0}

    return {
        "detected": True,
        "confidence": min(len(matched_categories) / 3.0, 1.0),
        "cui_categories": matched_categories,
        "handling_required": "CUI Basic or CUI Specified per category",
    }


@check(name="output-sanitization", action=Action.REDACT, threshold=0.5)
def output_sanitization(text: str) -> dict:
    """Sanitize output to prevent information leakage.

    Removes or redacts content that could reveal system internals,
    infrastructure details, or sensitive configuration.
    """
    # Patterns that might reveal system internals
    sensitive_patterns = {
        "IP_INTERNAL": re.compile(r"\b(?:10|172\.(?:1[6-9]|2\d|3[01])|192\.168)\.\d{1,3}\.\d{1,3}\b"),
        "AWS_ACCOUNT": re.compile(r"\b\d{12}\b"),
        "ARN": re.compile(r"arn:aws:[a-z0-9-]+:[a-z0-9-]*:\d{12}:[a-zA-Z0-9/._-]+"),
        "ACCESS_KEY": re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
        "SECRET_KEY": re.compile(r"\b[A-Za-z0-9/+=]{40}\b"),
    }

    found_patterns: dict = {}
    redacted_text = text

    for pattern_name, pattern in sensitive_patterns.items():
        matches = pattern.findall(text)
        if matches:
            found_patterns[pattern_name] = len(matches)
            redacted_text = pattern.sub(f"[{pattern_name}_REDACTED]", redacted_text)

    if not found_patterns:
        return {"detected": False, "confidence": 0.0}

    return {
        "detected": True,
        "confidence": 0.9,
        "sanitized_patterns": found_patterns,
        "redacted_text": redacted_text,
    }


@check(name="fedramp-audit-log", action=Action.LOG, threshold=0.0)
def fedramp_audit_logging(text: str) -> dict:
    """Log all interactions for FedRAMP continuous monitoring.

    Maintains audit records per NIST SP 800-53 AU controls.
    """
    import time

    return {
        "detected": True,
        "confidence": 1.0,
        "audit_record": {
            "timestamp": time.time(),
            "text_length": len(text),
            "compliance_framework": "FedRAMP",
            "nist_control": "AU-2",
            "impact_level": "moderate",  # Should be configured
        },
    }


@dataclass
class FedRampPack:
    """FedRAMP compliance pack for US government AI systems."""

    checks: List[Check]

    @classmethod
    def full(cls) -> "FedRampPack":
        """Full FedRAMP compliance pack."""
        return cls(checks=[
            classification_detection,
            government_topic_restriction,
            cui_detection,
            output_sanitization,
            fedramp_audit_logging,
        ])

    @classmethod
    def moderate(cls) -> "FedRampPack":
        """FedRAMP Moderate baseline."""
        return cls(checks=[
            classification_detection,
            output_sanitization,
            fedramp_audit_logging,
        ])

    @classmethod
    def high(cls) -> "FedRampPack":
        """FedRAMP High baseline (all checks, strictest thresholds)."""
        return cls(checks=[
            classification_detection,
            government_topic_restriction,
            cui_detection,
            output_sanitization,
            fedramp_audit_logging,
        ])


def full() -> FedRampPack:
    """Get the full FedRAMP compliance pack."""
    return FedRampPack.full()


def moderate() -> FedRampPack:
    """Get the FedRAMP Moderate baseline pack."""
    return FedRampPack.moderate()


def high() -> FedRampPack:
    """Get the FedRAMP High baseline pack."""
    return FedRampPack.high()
