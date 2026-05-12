/**
 * Middleware layer — integrate guardrails with any LLM provider.
 */

import { Action } from "../core/actions";
import { Pipeline } from "../core/pipeline";
import { CheckContext, createContext } from "../core/context";
import { PipelineResult } from "../core/result";

export interface MiddlewareOptions {
  pipeline: Pipeline;
  applyTo?: "input" | "output" | "both";
  onBlockResponse?: string;
}

export class GuardrailMiddleware {
  private pipeline: Pipeline;
  private applyTo: string;
  private onBlockResponse: string;

  constructor(options: MiddlewareOptions) {
    this.pipeline = options.pipeline;
    this.applyTo = options.applyTo || "both";
    this.onBlockResponse = options.onBlockResponse || "I cannot process this request due to content policy.";
  }

  async processInput(text: string, context?: CheckContext): Promise<PipelineResult> {
    if (this.applyTo === "input" || this.applyTo === "both") {
      return this.pipeline.run(text, context);
    }
    return { allowed: true, action: Action.PASS, checkResults: [], totalLatencyMs: 0, pipelineName: this.pipeline.name, metadata: {} };
  }

  async processOutput(text: string, context?: CheckContext): Promise<PipelineResult> {
    if (this.applyTo === "output" || this.applyTo === "both") {
      return this.pipeline.run(text, context);
    }
    return { allowed: true, action: Action.PASS, checkResults: [], totalLatencyMs: 0, pipelineName: this.pipeline.name, metadata: {} };
  }

  wrap<T extends (text: string, ...args: any[]) => any>(llmCall: T) {
    const middleware = this;
    return async (text: string, ...args: any[]) => {
      const inputResult = await middleware.processInput(text);
      if (!inputResult.allowed) {
        return { blocked: true, response: middleware.onBlockResponse, guardrailResult: inputResult };
      }

      const effectiveText = inputResult.modifiedText || text;
      const llmResponse = await llmCall(effectiveText, ...args);
      const responseText = typeof llmResponse === "string" ? llmResponse : String(llmResponse);

      const outputResult = await middleware.processOutput(responseText);
      if (!outputResult.allowed) {
        return { blocked: true, response: middleware.onBlockResponse, guardrailResult: outputResult };
      }

      return { blocked: false, response: outputResult.modifiedText || responseText };
    };
  }
}

export function wrapLlmCall<T extends (text: string, ...args: any[]) => any>(
  llmCall: T,
  pipeline: Pipeline,
  applyTo: "input" | "output" | "both" = "both"
) {
  const middleware = new GuardrailMiddleware({ pipeline, applyTo });
  return middleware.wrap(llmCall);
}
