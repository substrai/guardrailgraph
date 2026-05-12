/**
 * HIPAA Compliance Pack — healthcare AI safety guardrails.
 */

import { Action } from "../core/actions";
import { Check } from "../core/check";
import { piiCheck } from "../checks/pii";

const MEDICAL_CLAIM_KEYWORDS = [
  "you have", "you are diagnosed", "your diagnosis is",
  "i recommend", "you should take", "prescribe",
  "your condition", "treatment plan", "prognosis",
  "medical advice", "clinical recommendation",
];

function phiDetection(): Check {
  return piiCheck({
    entityTypes: ["SSN", "PHONE", "EMAIL", "DATE_OF_BIRTH", "IP_ADDRESS"],
    action: Action.REDACT,
    name: "phi-detection",
  });
}

function medicalClaimDetection(): Check {
  return new Check(
    (text: string) => {
      const textLower = text.toLowerCase();
      const matched = MEDICAL_CLAIM_KEYWORDS.filter((kw) => textLower.includes(kw));

      if (matched.length === 0) {
        return { detected: false, confidence: 0 };
      }

      return {
        detected: true,
        confidence: Math.min(matched.length / 3.0, 1.0),
        matchedClaims: matched,
        claimCount: matched.length,
      };
    },
    { name: "medical-claim-detection", action: Action.FLAG_FOR_REVIEW, threshold: 0.6 }
  );
}

function auditLogging(): Check {
  return new Check(
    (text: string) => ({
      detected: true,
      confidence: 1.0,
      auditRecord: { timestamp: Date.now(), textLength: text.length, action: "logged" },
    }),
    { name: "hipaa-audit-log", action: Action.LOG, threshold: 0 }
  );
}

export interface HipaaPack {
  checks: Check[];
}

export function full(): HipaaPack {
  return {
    checks: [phiDetection(), medicalClaimDetection(), auditLogging()],
  };
}

export function basic(): HipaaPack {
  return {
    checks: [phiDetection(), auditLogging()],
  };
}
