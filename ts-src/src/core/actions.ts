/**
 * Action definitions for guardrail check outcomes.
 */

export enum Action {
  PASS = "pass",
  BLOCK = "block",
  REDACT = "redact",
  FLAG_FOR_REVIEW = "flag_for_review",
  LOG = "log",
}

export function isBlocking(action: Action): boolean {
  return action === Action.BLOCK;
}

export function isModifying(action: Action): boolean {
  return action === Action.REDACT;
}
