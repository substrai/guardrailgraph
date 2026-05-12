/**
 * GuardrailGraph — Composable AI safety pipeline framework.
 *
 * @packageDocumentation
 */

// Core
export { Action, isBlocking, isModifying } from "./core/actions";
export { Check, check, CheckOptions, CheckFunction, CheckFunctionResult } from "./core/check";
export { Pipeline, pipeline, PipelineOptions } from "./core/pipeline";
export { CheckResult, PipelineResult, createCheckResult, createPipelineResult } from "./core/result";
export { CheckContext, createContext } from "./core/context";

// Built-in checks
export { piiCheck, PiiCheckOptions } from "./checks/pii";
export { toxicityCheck, ToxicityCheckOptions } from "./checks/toxicity";
export { topicCheck, TopicCheckOptions } from "./checks/topics";
export { injectionCheck, InjectionCheckOptions } from "./checks/injection";
export { costCheck, CostCheckOptions } from "./checks/cost";

// Industry packs
export * as hipaa from "./packs/hipaa";
export * as financial from "./packs/financial";

// Middleware
export { GuardrailMiddleware, MiddlewareOptions, wrapLlmCall } from "./middleware";
