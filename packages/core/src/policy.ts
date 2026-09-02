import type {
  ArgConstraint,
  AuthorizationDetail,
  Budget,
  Policy,
  PolicyRule,
} from "./types.js";

export interface ToolCallContext {
  upstream: string;
  tool: string;
  args: Record<string, unknown>;
  costUnits: number;
}

export type DecisionEffect = "allow" | "deny" | "require_approval";
export type DecisionSource = "token_bounds" | "rule" | "constraint" | "budget" | "default";

export interface Decision {
  effect: DecisionEffect;
  source: DecisionSource;
  reason: string;
  ruleId?: string;
}

/**
 * Full gate decision: the token's authorization_details bound what is even
 * *reachable*; policy rules then decide among reachable calls; default is deny.
 * Budget is checked separately (it is stateful) via `checkBudget`.
 */
export function decide(
  policy: Policy,
  call: ToolCallContext,
  tokenAuthorization: AuthorizationDetail[],
): Decision {
  if (!isWithinAuthorization(call, tokenAuthorization)) {
    return {
      effect: "deny",
      source: "token_bounds",
      reason: `tool ${call.upstream}.${call.tool} is outside the token's authorization_details`,
    };
  }
  return evaluatePolicy(policy, call);
}

export function isWithinAuthorization(
  call: Pick<ToolCallContext, "upstream" | "tool">,
  details: AuthorizationDetail[],
): boolean {
  return details.some(
    (d) => d.upstream === call.upstream && (d.tools.includes("*") || d.tools.includes(call.tool)),
  );
}

export function evaluatePolicy(policy: Policy, call: ToolCallContext): Decision {
  for (const [index, rule] of policy.rules.entries()) {
    if (!ruleMatches(rule, call)) continue;
    const ruleId = rule.id ?? `${policy.id}#${index}`;

    const maxCost = rule.constraints?.maxCostUnits;
    if (rule.effect === "allow" && maxCost !== undefined && call.costUnits > maxCost) {
      return {
        effect: "deny",
        source: "constraint",
        ruleId,
        reason: `call cost ${call.costUnits} exceeds rule maxCostUnits ${maxCost}`,
      };
    }

    return {
      effect: rule.effect,
      source: "rule",
      ruleId,
      reason: rule.description ?? `matched ${rule.effect} rule ${ruleId}`,
    };
  }
  return { effect: "deny", source: "default", reason: "no policy rule matched (default deny)" };
}

function ruleMatches(rule: PolicyRule, call: ToolCallContext): boolean {
  if (rule.match.upstream !== undefined && !globMatch(rule.match.upstream, call.upstream)) {
    return false;
  }
  if (rule.match.tool !== undefined && !globMatch(rule.match.tool, call.tool)) {
    return false;
  }
  if (rule.match.where !== undefined) {
    return rule.match.where.every((c) => constraintHolds(c, call.args));
  }
  return true;
}

/** Minimal glob: "*" matches any run of characters; everything else is literal. */
export function globMatch(pattern: string, value: string): boolean {
  if (pattern === "*") return true;
  const escaped = pattern.split("*").map(escapeRegExp).join(".*");
  return new RegExp(`^${escaped}$`).test(value);
}

function escapeRegExp(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

export function constraintHolds(constraint: ArgConstraint, args: Record<string, unknown>): boolean {
  const actual = getPath(args, constraint.path);
  const expected = constraint.value;
  switch (constraint.op) {
    case "eq":
      return actual === expected;
    case "neq":
      return actual !== expected;
    case "gt":
      return typeof actual === "number" && typeof expected === "number" && actual > expected;
    case "gte":
      return typeof actual === "number" && typeof expected === "number" && actual >= expected;
    case "lt":
      return typeof actual === "number" && typeof expected === "number" && actual < expected;
    case "lte":
      return typeof actual === "number" && typeof expected === "number" && actual <= expected;
    case "in":
      return Array.isArray(expected) && expected.some((v) => v === actual);
    case "contains":
      if (typeof actual === "string" && typeof expected === "string") {
        return actual.includes(expected);
      }
      return Array.isArray(actual) && actual.some((v) => v === expected);
    case "startsWith":
      return (
        typeof actual === "string" && typeof expected === "string" && actual.startsWith(expected)
      );
    case "matches":
      return (
        typeof actual === "string" &&
        typeof expected === "string" &&
        new RegExp(expected).test(actual)
      );
  }
}

export function getPath(obj: Record<string, unknown>, path: string): unknown {
  let current: unknown = obj;
  for (const segment of path.split(".")) {
    if (current === null || typeof current !== "object") return undefined;
    current = (current as Record<string, unknown>)[segment];
  }
  return current;
}

export interface BudgetCheck {
  ok: boolean;
  remainingUnits: number;
}

export function checkBudget(budget: Budget, costUnits: number): BudgetCheck {
  const remaining = budget.maxUnits - budget.spentUnits;
  return { ok: costUnits <= remaining, remainingUnits: remaining };
}
