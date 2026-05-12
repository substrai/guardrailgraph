/**
 * Pipeline builder and DAG executor — the orchestration engine.
 */

import { Action, isBlocking } from "./actions";
import { Check } from "./check";
import { CheckContext, createContext } from "./context";
import { CheckResult, PipelineResult } from "./result";

export interface PipelineOptions {
  name?: string;
  checks?: Check[];
  packs?: Array<{ checks: Check[] } | Check[]>;
  mode?: "fail-closed" | "fail-open" | "log-only";
  timeoutMs?: number;
  onBlock?: (result: PipelineResult) => void;
  onFlag?: (result: PipelineResult) => void;
  onPass?: (result: PipelineResult) => void;
  parallel?: boolean;
  metadata?: Record<string, any>;
}

export class Pipeline {
  readonly name: string;
  checks: Check[];
  readonly mode: string;
  readonly timeoutMs: number;
  readonly onBlock?: (result: PipelineResult) => void;
  readonly onFlag?: (result: PipelineResult) => void;
  readonly onPass?: (result: PipelineResult) => void;
  readonly parallel: boolean;
  readonly metadata: Record<string, any>;

  constructor(options: PipelineOptions = {}) {
    this.name = options.name || "default";
    this.checks = [];
    this.mode = options.mode || "fail-closed";
    this.timeoutMs = options.timeoutMs || 5000;
    this.onBlock = options.onBlock;
    this.onFlag = options.onFlag;
    this.onPass = options.onPass;
    this.parallel = options.parallel !== false;
    this.metadata = options.metadata || {};

    // Register checks
    if (options.checks) {
      for (const c of options.checks) {
        this.addCheck(c);
      }
    }

    // Register packs
    if (options.packs) {
      for (const pack of options.packs) {
        const packChecks = Array.isArray(pack) ? pack : pack.checks;
        for (const c of packChecks) {
          this.addCheck(c);
        }
      }
    }
  }

  addCheck(check: Check): this {
    this.checks.push(check);
    return this;
  }

  removeCheck(name: string): this {
    this.checks = this.checks.filter((c) => c.name !== name);
    return this;
  }

  async run(
    text: string,
    context?: CheckContext,
    metadata?: Record<string, any>
  ): Promise<PipelineResult> {
    const start = Date.now();
    const ctx = context || createContext({ pipelineName: this.name });
    if (metadata) {
      Object.assign(ctx.metadata, metadata);
    }

    // Build execution layers
    const layers = this.buildExecutionPlan();
    const allResults: CheckResult[] = [];
    let currentText = text;
    let blocked = false;

    for (const layer of layers) {
      if (blocked && this.mode === "fail-closed") break;

      let layerResults: CheckResult[];

      if (this.parallel && layer.length > 1) {
        layerResults = await Promise.all(
          layer.map((check) => check.execute(currentText, ctx))
        );
      } else {
        layerResults = [];
        for (const check of layer) {
          const result = await check.execute(currentText, ctx);
          layerResults.push(result);
        }
      }

      for (const result of layerResults) {
        allResults.push(result);

        if (result.detected && result.action === Action.REDACT && result.redactedText) {
          currentText = result.redactedText;
        }

        if (result.detected && isBlocking(result.action) && this.mode !== "log-only") {
          blocked = true;
        }
      }
    }

    const finalAction = this.determineFinalAction(allResults);
    const allowed = this.mode === "log-only" ? true : !blocked;

    const pipelineResult: PipelineResult = {
      allowed,
      action: finalAction,
      checkResults: allResults,
      modifiedText: currentText !== text ? currentText : undefined,
      originalText: text,
      totalLatencyMs: Date.now() - start,
      pipelineName: this.name,
      metadata: this.metadata,
    };

    // Fire callbacks
    if (!allowed && this.onBlock) this.onBlock(pipelineResult);
    else if (
      allResults.some((r) => r.detected && r.action === Action.FLAG_FOR_REVIEW) &&
      this.onFlag
    ) {
      this.onFlag(pipelineResult);
    } else if (allowed && this.onPass) {
      this.onPass(pipelineResult);
    }

    return pipelineResult;
  }

  private buildExecutionPlan(): Check[][] {
    if (this.checks.length === 0) return [];

    const checkMap = new Map(this.checks.map((c) => [c.name, c]));
    const inDegree = new Map(this.checks.map((c) => [c.name, 0]));
    const dependents = new Map<string, string[]>();

    for (const c of this.checks) {
      for (const dep of c.dependsOn) {
        if (checkMap.has(dep)) {
          inDegree.set(c.name, (inDegree.get(c.name) || 0) + 1);
          const deps = dependents.get(dep) || [];
          deps.push(c.name);
          dependents.set(dep, deps);
        }
      }
    }

    const layers: Check[][] = [];
    let ready = [...inDegree.entries()]
      .filter(([_, deg]) => deg === 0)
      .map(([name]) => name);

    while (ready.length > 0) {
      layers.push(ready.map((name) => checkMap.get(name)!));

      const nextReady: string[] = [];
      for (const name of ready) {
        for (const depName of dependents.get(name) || []) {
          const newDeg = (inDegree.get(depName) || 1) - 1;
          inDegree.set(depName, newDeg);
          if (newDeg === 0) nextReady.push(depName);
        }
      }
      ready = nextReady;
    }

    return layers;
  }

  private determineFinalAction(results: CheckResult[]): Action {
    const severity: Record<string, number> = {
      [Action.BLOCK]: 4,
      [Action.FLAG_FOR_REVIEW]: 3,
      [Action.REDACT]: 2,
      [Action.LOG]: 1,
      [Action.PASS]: 0,
    };

    let maxAction = Action.PASS;
    let maxSeverity = 0;

    for (const result of results) {
      if (result.detected) {
        const s = severity[result.action] || 0;
        if (s > maxSeverity) {
          maxSeverity = s;
          maxAction = result.action;
        }
      }
    }

    return maxAction;
  }
}

/**
 * Create a guardrail pipeline.
 */
export function pipeline(options: PipelineOptions = {}): Pipeline {
  return new Pipeline(options);
}
