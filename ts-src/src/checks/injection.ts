/**
 * Built-in prompt injection detection check.
 */

import { Action } from "../core/actions";
import { Check } from "../core/check";

interface PatternGroup {
  name: string;
  patterns: RegExp[];
  severity: number;
  category: string;
}

const INJECTION_PATTERNS: PatternGroup[] = [
  {
    name: "instruction_override",
    patterns: [
      /ignore\s+(all\s+)?(previous|prior|above)\s+(instructions?|prompts?|rules?)/i,
      /disregard\s+(all\s+)?(previous|prior|above)/i,
      /forget\s+(everything|all|your)\s+(instructions?|rules?|training)/i,
      /override\s+(your|the|all)\s+(instructions?|rules?|constraints?)/i,
      /new\s+instructions?\s*:/i,
    ],
    severity: 0.95,
    category: "override",
  },
  {
    name: "role_manipulation",
    patterns: [
      /you\s+are\s+now\s+(?:a\s+)?(?:DAN|evil|unrestricted|jailbroken)/i,
      /pretend\s+(?:you\s+are|to\s+be)\s+(?:a\s+)?(?:different|evil|unrestricted)/i,
      /act\s+as\s+(?:if|though)\s+you\s+(?:have\s+)?no\s+(?:rules|restrictions|limits)/i,
      /enter\s+(?:DAN|developer|admin|god)\s+mode/i,
    ],
    severity: 0.9,
    category: "role_play",
  },
  {
    name: "system_prompt_extraction",
    patterns: [
      /(?:show|reveal|display|print|output)\s+(?:me\s+)?(?:your|the)\s+(?:system\s+)?(?:prompt|instructions)/i,
      /what\s+(?:are|is)\s+your\s+(?:system\s+)?(?:prompt|instructions|rules)/i,
      /repeat\s+(?:your|the)\s+(?:system\s+)?(?:prompt|instructions)\s+(?:back|verbatim)/i,
    ],
    severity: 0.8,
    category: "extraction",
  },
  {
    name: "delimiter_injection",
    patterns: [
      /<\/?system>/i,
      /\[\/?INST\]/i,
      /```\s*system/i,
      /<\|(?:im_start|im_end|system|endoftext)\|>/i,
    ],
    severity: 0.85,
    category: "delimiter",
  },
];

export interface InjectionCheckOptions {
  sensitivity?: "low" | "medium" | "high";
  action?: Action;
  threshold?: number;
  name?: string;
}

export function injectionCheck(options: InjectionCheckOptions = {}): Check {
  const {
    sensitivity = "high",
    action = Action.BLOCK,
    threshold = 0.6,
    name = "prompt-injection",
  } = options;

  const thresholdMap: Record<string, number> = { low: 0.9, medium: 0.75, high: 0.6 };
  const sensitivityThreshold = thresholdMap[sensitivity] || 0.75;

  return new Check(
    (text: string) => {
      const matches: Array<{ name: string; category: string; severity: number }> = [];
      let maxSeverity = 0;

      for (const group of INJECTION_PATTERNS) {
        for (const pattern of group.patterns) {
          if (pattern.test(text)) {
            matches.push({ name: group.name, category: group.category, severity: group.severity });
            maxSeverity = Math.max(maxSeverity, group.severity);
            break;
          }
        }
      }

      const detected = maxSeverity >= sensitivityThreshold;

      return {
        detected,
        confidence: maxSeverity,
        matches,
        matchCount: matches.length,
        categories: [...new Set(matches.map((m) => m.category))],
      };
    },
    { name, action, threshold }
  );
}
