/**
 * Built-in toxicity detection check.
 */

import { Action } from "../core/actions";
import { Check } from "../core/check";

const TOXICITY_KEYWORDS: Record<string, string[]> = {
  hate: ["hate", "racist", "bigot", "supremacist", "inferior race", "ethnic slur", "discrimination"],
  violence: ["kill", "murder", "attack", "bomb", "shoot", "stab", "assault", "destroy", "weapon", "explosive"],
  sexual: ["explicit", "pornographic", "nude", "sexual act"],
  self_harm: ["suicide", "self-harm", "cut myself", "end my life", "kill myself", "overdose"],
  harassment: ["threaten", "bully", "stalk", "intimidate", "harass", "doxx", "blackmail"],
};

const CATEGORY_WEIGHTS: Record<string, number> = {
  hate: 0.9,
  violence: 0.95,
  sexual: 0.7,
  self_harm: 1.0,
  harassment: 0.85,
};

export interface ToxicityCheckOptions {
  categories?: string[];
  threshold?: number;
  action?: Action;
  name?: string;
}

export function toxicityCheck(options: ToxicityCheckOptions = {}): Check {
  const {
    categories,
    threshold = 0.7,
    action = Action.BLOCK,
    name = "toxicity",
  } = options;

  const activeCategories = categories || Object.keys(TOXICITY_KEYWORDS);

  return new Check(
    (text: string) => {
      const textLower = text.toLowerCase();
      const categoryScores: Record<string, number> = {};
      const matchedTerms: Record<string, string[]> = {};

      for (const category of activeCategories) {
        const keywords = TOXICITY_KEYWORDS[category] || [];
        const matches = keywords.filter((kw) => textLower.includes(kw));

        if (matches.length > 0) {
          const weight = CATEGORY_WEIGHTS[category] || 0.8;
          categoryScores[category] = Math.min(matches.length / 3.0, 1.0) * weight;
          matchedTerms[category] = matches;
        } else {
          categoryScores[category] = 0;
        }
      }

      const overallScore = Math.max(...Object.values(categoryScores), 0);

      return {
        detected: overallScore >= threshold,
        confidence: overallScore,
        categoryScores,
        matchedTerms,
      };
    },
    { name, action, threshold }
  );
}
