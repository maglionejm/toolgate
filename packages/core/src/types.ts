import { z } from "zod";

// ---------------------------------------------------------------------------
// Tool + upstream registry
// ---------------------------------------------------------------------------

export const ToolDefSchema = z.object({
  name: z.string().min(1),
  description: z.string().optional(),
  /** Side-effecting tools are the ones worth gating hardest (writes, sends, payments). */
  sideEffecting: z.boolean().default(false),
  /** Abstract cost of one invocation, charged against the grant budget. */
  costUnits: z.number().int().min(0).default(1),
});
export type ToolDef = z.infer<typeof ToolDefSchema>;

/**
 * How the gate injects the real credential into the upstream request.
 * The secret itself lives in the vault under `secretRef` — never in this object.
 */
export const CredentialInjectionSchema = z.discriminatedUnion("mode", [
  z.object({ mode: z.literal("bearer"), secretRef: z.string() }),
  z.object({ mode: z.literal("header"), headerName: z.string(), secretRef: z.string() }),
  z.object({ mode: z.literal("query"), paramName: z.string(), secretRef: z.string() }),
]);
export type CredentialInjection = z.infer<typeof CredentialInjectionSchema>;

export const UpstreamSchema = z.object({
  id: z.string(),
  tenantId: z.string(),
  /** Stable name used in tokens/policies, e.g. "crm" or "email". */
  name: z.string().min(1),
  baseUrl: z.url(),
  credential: CredentialInjectionSchema,
  tools: z.array(ToolDefSchema),
  createdAt: z.iso.datetime(),
});
export type Upstream = z.infer<typeof UpstreamSchema>;

// ---------------------------------------------------------------------------
// Principals
// ---------------------------------------------------------------------------

export const TenantSchema = z.object({
  id: z.string(),
  name: z.string().min(1),
  createdAt: z.iso.datetime(),
});
export type Tenant = z.infer<typeof TenantSchema>;

export const UserSchema = z.object({
  id: z.string(),
  tenantId: z.string(),
  displayName: z.string().min(1),
  email: z.email().optional(),
  createdAt: z.iso.datetime(),
});
export type User = z.infer<typeof UserSchema>;

export const AgentIdentitySchema = z.object({
  id: z.string(),
  tenantId: z.string(),
  name: z.string().min(1),
  /** Ed25519 public JWK; the agent proves possession of the private half. */
  publicJwk: z.record(z.string(), z.unknown()),
  status: z.enum(["active", "disabled"]),
  createdAt: z.iso.datetime(),
});
export type AgentIdentity = z.infer<typeof AgentIdentitySchema>;

// ---------------------------------------------------------------------------
// Authorization details (RFC 9396-flavored) and delegation grants
// ---------------------------------------------------------------------------

export const AuthorizationDetailSchema = z.object({
  type: z.literal("toolgate:tool_call").default("toolgate:tool_call"),
  /** Upstream name this detail applies to. */
  upstream: z.string().min(1),
  /** Tool names, or ["*"] for all tools on the upstream. */
  tools: z.array(z.string().min(1)).min(1),
});
export type AuthorizationDetail = z.infer<typeof AuthorizationDetailSchema>;

export const BudgetSchema = z.object({
  maxUnits: z.number().int().positive(),
  spentUnits: z.number().int().min(0).default(0),
});
export type Budget = z.infer<typeof BudgetSchema>;

/**
 * A delegation grant is the durable record of a human delegating bounded
 * authority to an agent: which tools, how much budget, until when.
 * Capability tokens are minted *from* grants and are always narrower or equal.
 */
export const DelegationGrantSchema = z.object({
  id: z.string(),
  tenantId: z.string(),
  userId: z.string(),
  agentId: z.string(),
  scopes: z.array(z.string()),
  authorization: z.array(AuthorizationDetailSchema).min(1),
  budget: BudgetSchema,
  /** Policy applied at the gate for calls under this grant. */
  policyId: z.string(),
  expiresAt: z.iso.datetime(),
  status: z.enum(["active", "revoked"]),
  createdAt: z.iso.datetime(),
});
export type DelegationGrant = z.infer<typeof DelegationGrantSchema>;

// ---------------------------------------------------------------------------
// Policy
// ---------------------------------------------------------------------------

export const ArgConstraintSchema = z.object({
  /** Dot path into the tool call arguments, e.g. "to.email" or "amount". */
  path: z.string().min(1),
  op: z.enum(["eq", "neq", "gt", "gte", "lt", "lte", "in", "contains", "startsWith", "matches"]),
  value: z.unknown(),
});
export type ArgConstraint = z.infer<typeof ArgConstraintSchema>;

export const PolicyRuleSchema = z.object({
  id: z.string().optional(),
  description: z.string().optional(),
  effect: z.enum(["allow", "deny", "require_approval"]),
  match: z.object({
    /** Glob over upstream name ("*" matches any run of characters). Absent = any. */
    upstream: z.string().optional(),
    /** Glob over tool name. Absent = any. */
    tool: z.string().optional(),
    /** All constraints must hold for the rule to match. */
    where: z.array(ArgConstraintSchema).optional(),
  }),
  constraints: z
    .object({
      /** Calls costing more than this are denied even when the rule allows. */
      maxCostUnits: z.number().int().positive().optional(),
    })
    .optional(),
});
export type PolicyRule = z.infer<typeof PolicyRuleSchema>;

export const PolicySchema = z.object({
  id: z.string(),
  tenantId: z.string(),
  name: z.string().min(1),
  /** Rules are evaluated in order; first match wins. No match = deny. */
  rules: z.array(PolicyRuleSchema),
  createdAt: z.iso.datetime(),
});
export type Policy = z.infer<typeof PolicySchema>;

// ---------------------------------------------------------------------------
// Approvals (async human-in-the-loop, CIBA-style)
// ---------------------------------------------------------------------------

export const ApprovalRequestSchema = z.object({
  id: z.string(),
  tenantId: z.string(),
  callId: z.string(),
  grantId: z.string(),
  agentId: z.string(),
  userId: z.string(),
  upstream: z.string(),
  tool: z.string(),
  args: z.record(z.string(), z.unknown()),
  status: z.enum(["pending", "approved", "denied", "expired", "executed"]),
  requestedAt: z.iso.datetime(),
  expiresAt: z.iso.datetime(),
  decidedAt: z.iso.datetime().optional(),
  decidedBy: z.string().optional(),
  executedAt: z.iso.datetime().optional(),
});
export type ApprovalRequest = z.infer<typeof ApprovalRequestSchema>;

// ---------------------------------------------------------------------------
// Capability token claims
// ---------------------------------------------------------------------------

/**
 * RFC 8693 delegation semantics: `sub` stays the human principal the work is
 * for; `act.sub` is the agent actually acting. The agent never receives the
 * user's credentials — only this narrow, short-lived, sender-bound token.
 */
export const CapabilityClaimsSchema = z.looseObject({
  iss: z.string(),
  sub: z.string(),
  aud: z.string(),
  exp: z.number(),
  iat: z.number(),
  jti: z.string(),
  tenant: z.string(),
  grant_id: z.string(),
  act: z.object({ sub: z.string() }),
  scope: z.string(),
  authorization_details: z.array(AuthorizationDetailSchema),
  /** Confirmation claim (RFC 7800): JWK thumbprint of the agent key that must sign call proofs. */
  cnf: z.object({ jkt: z.string() }),
  /** Per-task transaction id (Transaction Tokens alignment) — the join key for the audit trail. */
  txn: z.string(),
  tg_ver: z.literal(1),
});
export type CapabilityClaims = z.infer<typeof CapabilityClaimsSchema>;

// ---------------------------------------------------------------------------
// Audit
// ---------------------------------------------------------------------------

export const AuditDecisionSchema = z.object({
  effect: z.enum(["allow", "deny", "require_approval"]),
  source: z.enum(["token_bounds", "rule", "constraint", "budget", "approval", "default"]),
  ruleId: z.string().optional(),
  reason: z.string(),
});
export type AuditDecision = z.infer<typeof AuditDecisionSchema>;

export const AuditResultSchema = z.object({
  status: z.enum(["executed", "denied", "pending_approval", "error"]),
  httpStatus: z.number().int().optional(),
  latencyMs: z.number().optional(),
  costUnits: z.number().int().optional(),
});
export type AuditResult = z.infer<typeof AuditResultSchema>;

export const AuditRecordSchema = z.object({
  seq: z.number().int().positive(),
  id: z.string(),
  tenantId: z.string(),
  ts: z.iso.datetime(),
  actor: z.object({
    agentId: z.string(),
    userId: z.string(),
    grantId: z.string(),
    tokenJti: z.string(),
  }),
  action: z.object({
    callId: z.string(),
    upstream: z.string(),
    tool: z.string(),
    /** SHA-256 of canonical args — proves what was requested without storing payloads. */
    argsHash: z.string(),
  }),
  decision: AuditDecisionSchema,
  result: AuditResultSchema,
  prevHash: z.string(),
  hash: z.string(),
  sig: z.string(),
});
export type AuditRecord = z.infer<typeof AuditRecordSchema>;
export type AuditRecordInput = Omit<AuditRecord, "seq" | "prevHash" | "hash" | "sig">;
