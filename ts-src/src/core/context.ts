/**
 * Check execution context — provides runtime info to checks.
 */

export interface CheckContext {
  pipelineName: string;
  environment: string;
  config: Record<string, any>;
  metadata: Record<string, any>;
  shared: Record<string, any>;
}

export function createContext(partial?: Partial<CheckContext>): CheckContext {
  return {
    pipelineName: "",
    environment: "dev",
    config: {},
    metadata: {},
    shared: {},
    ...partial,
  };
}
