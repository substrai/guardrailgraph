/**
 * Result types for check execution and pipeline outcomes.
 */

import { Action } from "./actions";

export interface CheckResult {
  name: string;
  detected: boolean;
  confidence: number;
  action: Action;
  details: Record<string, any>;
  latencyMs: number;
  redactedText?: string;
  error?: string;
}

export interface PipelineResult {
  allowed: boolean;
  action: Action;
  checkResults: CheckResult[];
  modifiedText?: string;
  originalText?: string;
  totalLatencyMs: number;
  pipelineName: string;
  metadata: Record<string, any>;
}

export function createCheckResult(partial: Partial<CheckResult> & { name: string }): CheckResult {
  return {
    detected: false,
    confidence: 0,
    action: Action.PASS,
    details: {},
    latencyMs: 0,
    ...partial,
  };
}

export function createPipelineResult(partial: Partial<PipelineResult>): PipelineResult {
  return {
    allowed: true,
    action: Action.PASS,
    checkResults: [],
    totalLatencyMs: 0,
    pipelineName: "",
    metadata: {},
    ...partial,
  };
}
