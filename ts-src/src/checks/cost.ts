/**
 * Built-in cost limiting check.
 */

import { Action } from "../core/actions";
import { Check } from "../core/check";

export interface CostCheckOptions {
  maxTokensPerRequest?: number;
  maxCostPerRequest?: number;
  costPer1kInputTokens?: number;
  action?: Action;
  threshold?: number;
  name?: string;
}

export function costCheck(options: CostCheckOptions = {}): Check {
  const {
    maxTokensPerRequest = 4000,
    maxCostPerRequest = 0.10,
    costPer1kInputTokens = 0.00025,
    action = Action.BLOCK,
    threshold = 0.5,
    name = "cost-limit",
  } = options;

  return new Check(
    (text: string) => {
      const estimatedTokens = Math.max(1, Math.floor(text.length / 4));
      const estimatedCost = (estimatedTokens / 1000) * costPer1kInputTokens;

      const tokenExceeded = estimatedTokens > maxTokensPerRequest;
      const costExceeded = estimatedCost > maxCostPerRequest;
      const detected = tokenExceeded || costExceeded;

      return {
        detected,
        confidence: detected ? 1.0 : 0.0,
        estimatedTokens,
        estimatedCostUsd: estimatedCost,
        maxTokens: maxTokensPerRequest,
        maxCostUsd: maxCostPerRequest,
        tokenExceeded,
        costExceeded,
      };
    },
    { name, action, threshold }
  );
}
