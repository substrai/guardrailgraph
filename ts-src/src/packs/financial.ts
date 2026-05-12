/**
 * Financial Compliance Pack — SOX guardrails.
 */

import { Action } from "../core/actions";
import { Check } from "../core/check";

const FINANCIAL_ADVICE_KEYWORDS = [
  "you should invest", "buy this stock", "sell your",
  "guaranteed returns", "financial advice", "investment recommendation",
  "i recommend buying", "this stock will", "market prediction",
  "insider tip", "sure thing", "can't lose",
];

const INSIDER_KEYWORDS = [
  "insider information", "non-public", "material information",
  "before the announcement", "confidential deal", "merger talks",
  "earnings surprise", "undisclosed", "tip from",
];

function financialAdviceDetection(): Check {
  return new Check(
    (text: string) => {
      const textLower = text.toLowerCase();
      const matched = FINANCIAL_ADVICE_KEYWORDS.filter((kw) => textLower.includes(kw));

      if (matched.length === 0) return { detected: false, confidence: 0 };

      return {
        detected: true,
        confidence: Math.min(matched.length / 2.0, 1.0),
        matchedKeywords: matched,
        category: "financial_advice",
      };
    },
    { name: "financial-advice-detection", action: Action.BLOCK, threshold: 0.6 }
  );
}

function insiderInfoDetection(): Check {
  return new Check(
    (text: string) => {
      const textLower = text.toLowerCase();
      const matched = INSIDER_KEYWORDS.filter((kw) => textLower.includes(kw));

      if (matched.length === 0) return { detected: false, confidence: 0 };

      return {
        detected: true,
        confidence: Math.min(matched.length / 2.0, 1.0),
        matchedKeywords: matched,
        category: "insider_information",
      };
    },
    { name: "insider-info-detection", action: Action.BLOCK, threshold: 0.7 }
  );
}

function soxAuditLogging(): Check {
  return new Check(
    (text: string) => ({
      detected: true,
      confidence: 1.0,
      auditRecord: { timestamp: Date.now(), textLength: text.length, framework: "SOX" },
    }),
    { name: "sox-audit-log", action: Action.LOG, threshold: 0 }
  );
}

export interface FinancialPack {
  checks: Check[];
}

export function sox(): FinancialPack {
  return {
    checks: [financialAdviceDetection(), insiderInfoDetection(), soxAuditLogging()],
  };
}
