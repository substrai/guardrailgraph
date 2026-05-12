/**
 * Built-in PII detection and redaction check.
 */

import { Action } from "../core/actions";
import { Check } from "../core/check";

interface PiiEntity {
  type: string;
  value: string;
  start: number;
  end: number;
  confidence: number;
}

const PII_PATTERNS: Record<string, RegExp> = {
  SSN: /\b\d{3}-\d{2}-\d{4}\b/g,
  PHONE: /\b(?:\+1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b/g,
  EMAIL: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/g,
  CREDIT_CARD: /\b(?:\d{4}[-\s]?){3}\d{4}\b/g,
  IP_ADDRESS: /\b(?:\d{1,3}\.){3}\d{1,3}\b/g,
  DATE_OF_BIRTH: /\b(?:0[1-9]|1[0-2])[/-](?:0[1-9]|[12]\d|3[01])[/-](?:19|20)\d{2}\b/g,
};

export interface PiiCheckOptions {
  entityTypes?: string[];
  redactionChar?: string;
  sensitivity?: string;
  action?: Action;
  threshold?: number;
  name?: string;
}

function detectPii(text: string, entityTypes?: string[]): PiiEntity[] {
  const entities: PiiEntity[] = [];
  const patterns = entityTypes
    ? Object.entries(PII_PATTERNS).filter(([k]) => entityTypes.includes(k))
    : Object.entries(PII_PATTERNS);

  for (const [type, pattern] of patterns) {
    const regex = new RegExp(pattern.source, pattern.flags);
    let match: RegExpExecArray | null;
    while ((match = regex.exec(text)) !== null) {
      entities.push({
        type,
        value: match[0],
        start: match.index,
        end: match.index + match[0].length,
        confidence: 0.95,
      });
    }
  }

  return entities.sort((a, b) => a.start - b.start);
}

function redactText(text: string, entities: PiiEntity[]): string {
  let result = text;
  const sorted = [...entities].sort((a, b) => b.start - a.start);
  for (const entity of sorted) {
    result = result.slice(0, entity.start) + `[${entity.type}]` + result.slice(entity.end);
  }
  return result;
}

export function piiCheck(options: PiiCheckOptions = {}): Check {
  const { entityTypes, action = Action.REDACT, threshold = 0.5, name = "pii-detection" } = options;

  return new Check(
    (text: string) => {
      const entities = detectPii(text, entityTypes);
      if (entities.length === 0) {
        return { detected: false, confidence: 0 };
      }

      const maxConfidence = Math.max(...entities.map((e) => e.confidence));
      const redacted = redactText(text, entities);

      return {
        detected: true,
        confidence: maxConfidence,
        entities: entities.map((e) => ({ type: e.type, value: e.value })),
        redactedText: redacted,
        entityCount: entities.length,
        entityTypes: [...new Set(entities.map((e) => e.type))],
      };
    },
    { name, action, threshold }
  );
}
