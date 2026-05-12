/**
 * The Check class and check() factory — turns functions into guardrail checks.
 */

import { Action, isBlocking } from "./actions";
import { CheckContext, createContext } from "./context";
import { CheckResult } from "./result";

export type CheckFunction = (text: string, context?: CheckContext) => CheckFunctionResult | Promise<CheckFunctionResult>;

export type CheckFunctionResult = {
  detected: boolean;
  confidence: number;
  redactedText?: string;
  [key: string]: any;
} | boolean;

export interface CheckOptions {
  name?: string;
  action?: Action;
  threshold?: number;
  description?: string;
  tags?: string[];
  dependsOn?: string[];
  timeoutMs?: number;
}

export class Check {
  readonly name: string;
  readonly action: Action;
  readonly threshold: number;
  readonly description: string;
  readonly tags: string[];
  readonly dependsOn: string[];
  readonly timeoutMs?: number;
  private readonly fn: CheckFunction;

  constructor(fn: CheckFunction, options: CheckOptions = {}) {
    this.fn = fn;
    this.name = options.name || fn.name || "unnamed-check";
    this.action = options.action || Action.BLOCK;
    this.threshold = options.threshold ?? 0.5;
    this.description = options.description || "";
    this.tags = options.tags || [];
    this.dependsOn = options.dependsOn || [];
    this.timeoutMs = options.timeoutMs;
  }

  async execute(text: string, context?: CheckContext): Promise<CheckResult> {
    const start = Date.now();
    const ctx = context || createContext();

    try {
      const raw = await this.fn(text, ctx);
      const result = this.normalizeResult(raw);
      result.latencyMs = Date.now() - start;
      return result;
    } catch (err: any) {
      return {
        name: this.name,
        detected: false,
        confidence: 0,
        action: Action.PASS,
        details: {},
        latencyMs: Date.now() - start,
        error: `Check failed: ${err.message || err}`,
      };
    }
  }

  executeSync(text: string, context?: CheckContext): CheckResult {
    // For sync contexts, we run the function directly if it's not async
    const start = Date.now();
    const ctx = context || createContext();

    try {
      const raw = this.fn(text, ctx);
      if (raw instanceof Promise) {
        throw new Error("Cannot run async check synchronously. Use execute() instead.");
      }
      const result = this.normalizeResult(raw);
      result.latencyMs = Date.now() - start;
      return result;
    } catch (err: any) {
      return {
        name: this.name,
        detected: false,
        confidence: 0,
        action: Action.PASS,
        details: {},
        latencyMs: Date.now() - start,
        error: `Check failed: ${err.message || err}`,
      };
    }
  }

  private normalizeResult(raw: CheckFunctionResult): CheckResult {
    if (typeof raw === "boolean") {
      return {
        name: this.name,
        detected: raw,
        confidence: raw ? 1.0 : 0.0,
        action: raw ? this.action : Action.PASS,
        details: {},
        latencyMs: 0,
      };
    }

    const detected = raw.detected && raw.confidence >= this.threshold;
    const { detected: _d, confidence: _c, redactedText, ...rest } = raw;

    return {
      name: this.name,
      detected,
      confidence: raw.confidence,
      action: detected ? this.action : Action.PASS,
      details: rest,
      latencyMs: 0,
      redactedText: redactedText,
    };
  }
}

/**
 * Factory function to create a Check instance.
 */
export function check(options: CheckOptions = {}) {
  return (fn: CheckFunction): Check => {
    return new Check(fn, {
      ...options,
      name: options.name || fn.name?.replace(/_/g, "-") || "unnamed-check",
    });
  };
}
