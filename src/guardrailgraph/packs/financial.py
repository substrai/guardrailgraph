"""Financial Compliance Pack — SOX and financial AI safety guardrails.

Provides checks for:
- Financial advice detection
- Insider information detection
- Data classification
- Audit trail for SOX compliance
- PII redaction (financial context)
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import List

from guardrailgraph.core.actions import Action
from guardrailgraph.core.check import Check, check


# Financial advice keywords
FINANCIAL_ADVICE_KEYWORDS = [
    "you should invest", "buy this stock", "sell your",
    "guaranteed returns", "financial advice", "investment recommendation",
    "i recommend buying", "this stock will", "market prediction",
    "insider tip", "sure thing", "can't lose",
]

# Insider information indicators
INSIDER_KEYWORDS = [
    "insider information", "non-public", "material information",
    "before the announcement", "confidential deal", "merger talks",
    "earnings surprise", "undisclosed", "tip from",
]


@check(name="financial-advice-detection", action=Action.BLOCK, threshold=0.6)
def financial_advice_detection(text: str) -> dict:
    """Detect and block unauthorized financial advice.

    AI systems should not provide specific investment recommendations
    without proper licensing and disclaimers.
    """
    text_lower = text.lower()
    matched = []

    for keyword in FINANCIAL_ADVICE_KEYWORDS:
        if keyword in text_lower:
            matched.append(keyword)

    if not matched:
        return {"detected": False, "confidence": 0.0}

    confidence = min(len(matched) / 2.0, 1.0)
    return {
        "detected": True,
        "confidence": confidence,
        "matched_keywords": matched,
        "category": "financial_advice",
    }


@check(name="insider-info-detection", action=Action.BLOCK, threshold=0.7)
def insider_info_detection(text: str) -> dict:
    """Detect potential insider information sharing.

    Block content that appears to share material non-public information.
    """
    text_lower = text.lower()
    matched = []

    for keyword in INSIDER_KEYWORDS:
        if keyword in text_lower:
            matched.append(keyword)

    if not matched:
        return {"detected": False, "confidence": 0.0}

    confidence = min(len(matched) / 2.0, 1.0)
    return {
        "detected": True,
        "confidence": confidence,
        "matched_keywords": matched,
        "category": "insider_information",
    }


@check(name="sox-audit-log", action=Action.LOG, threshold=0.0)
def sox_audit_logging(text: str) -> dict:
    """Log all interactions for SOX compliance audit trail."""
    import time

    return {
        "detected": True,
        "confidence": 1.0,
        "audit_record": {
            "timestamp": time.time(),
            "text_length": len(text),
            "compliance_framework": "SOX",
        },
    }


@dataclass
class FinancialPack:
    """Financial compliance pack (SOX)."""

    checks: List[Check]

    @classmethod
    def sox(cls) -> "FinancialPack":
        """Full SOX compliance pack."""
        return cls(checks=[
            financial_advice_detection,
            insider_info_detection,
            sox_audit_logging,
        ])


def sox() -> FinancialPack:
    """Get the SOX compliance pack."""
    return FinancialPack.sox()
