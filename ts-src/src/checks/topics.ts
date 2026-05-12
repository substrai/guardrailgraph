/**
 * Built-in topic restriction check.
 */

import { Action } from "../core/actions";
import { Check } from "../core/check";

export interface TopicCheckOptions {
  blockedTopics?: string[];
  allowedTopics?: string[];
  mode?: "blocklist" | "allowlist";
  action?: Action;
  threshold?: number;
  name?: string;
}

export function topicCheck(options: TopicCheckOptions = {}): Check {
  const {
    blockedTopics = [],
    allowedTopics = [],
    mode = "blocklist",
    action = Action.BLOCK,
    threshold = 0.5,
    name = "topic-restriction",
  } = options;

  return new Check(
    (text: string) => {
      const textLower = text.toLowerCase();

      if (mode === "blocklist") {
        const matched = blockedTopics.filter((t) => textLower.includes(t.toLowerCase()));
        return {
          detected: matched.length > 0,
          confidence: matched.length > 0 ? 1.0 : 0.0,
          matchedTopics: matched,
          mode: "blocklist",
        };
      } else {
        const matched = allowedTopics.filter((t) => textLower.includes(t.toLowerCase()));
        if (matched.length > 0) {
          return { detected: false, confidence: 0, matchedTopics: matched, mode: "allowlist" };
        }
        return {
          detected: true,
          confidence: 0.8,
          matchedTopics: [],
          mode: "allowlist",
          reason: "Content does not match any allowed topic",
        };
      }
    },
    { name, action, threshold }
  );
}
