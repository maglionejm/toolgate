import { Hono } from "hono";
import { z } from "zod";
import {
  ErrorCodes,
  ToolgateError,
  decide,
  hashArgs,
  newId,
  verifyCapabilityToken,
  verifyPopProof,
  type ApprovalRequest,
  type AuditDecision,
  type CapabilityClaims,
  type DelegationGrant,
  type ToolDef,
  type Upstream,
} from "@toolgate/core";
import type { AppContext } from "./context.js";

const CallBodySchema = z.object({
  tool: z.string().min(1),
  args: z.record(z.string(), z.unknown()).default({}),
});

interface AuthedCall {
  claims: CapabilityClaims;
  grant: DelegationGrant;
}

export function gateRoutes(ctx: AppContext): Hono {
  const app = new Hono();

  app.post("/call/:upstream", async (c) => {
    const upstreamName = c.req.param("upstream");
    const rawBody = await c.req.json().catch(() => {
      throw new ToolgateError(ErrorCodes.VALIDATION, "request body must be JSON");
    });
    const parsed = CallBodySchema.safeParse(rawBody);
    if (!parsed.success) {
      throw new ToolgateError(ErrorCodes.VALIDATION, "invalid call body", {
        issues: parsed.error.issues.map((i) => `${i.path.join(".")}: ${i.message}`),
      });
    }
    const { tool, args } = parsed.data;

    const { claims, grant } = await authenticate(ctx, c.req.raw, `/v1/gate/call/${upstreamName}`);
    const { upstream, toolDef } = resolveTool(ctx, claims.tenant, upstreamName, tool);

    const callId = newId("call");
    const call = { upstream: upstreamName, tool, args, costUnits: toolDef.costUnits };
    const policy = ctx.store.getPolicy(grant.policyId);
    if (!policy) throw new ToolgateError(ErrorCodes.INTERNAL, "grant policy missing");

    const decision = decide(policy, call, claims.authorization_details);
    const auditBase = {
      id: newId("evt"),
      tenantId: claims.tenant,
      ts: new Date().toISOString(),
      actor: {
        agentId: claims.act.sub,
        userId: claims.sub,
        grantId: grant.id,
        tokenJti: claims.jti,
      },
      action: { callId, upstream: upstreamName, tool, argsHash: hashArgs(args) },
    };

    if (decision.effect === "deny") {
      ctx.audit.record({
        ...auditBase,
        decision: toAuditDecision(decision),
        result: { status: "denied" },
      });
      throw new ToolgateError(ErrorCodes.DENIED, decision.reason, {
        source: decision.source,
        ...(decision.ruleId ? { ruleId: decision.ruleId } : {}),
      });
    }

    if (decision.effect === "require_approval") {
      const approval: ApprovalRequest = {
        id: newId("apr"),
        tenantId: claims.tenant,
        callId,
        grantId: grant.id,
        agentId: claims.act.sub,
        userId: claims.sub,
        upstream: upstreamName,
        tool,
        args,
        status: "pending",
        requestedAt: new Date().toISOString(),
        expiresAt: new Date(Date.now() + ctx.config.approvalTtlSeconds * 1000).toISOString(),
      };
      ctx.store.putApproval(approval);
      ctx.audit.record({
        ...auditBase,
        decision: toAuditDecision(decision),
        result: { status: "pending_approval" },
      });
      return c.json(
        {
          status: "pending_approval",
          approval_id: approval.id,
          expires_at: approval.expiresAt,
          reason: decision.reason,
        },
        202,
      );
    }

    const result = await executeCall(ctx, {
      auditBase,
      decision: toAuditDecision(decision),
      grant,
      upstream,
      toolDef,
      tool,
      args,
    });
    return c.json({ status: "executed", call_id: callId, result });
  });

  app.get("/approvals/:id", async (c) => {
    const { claims } = await authenticateTokenOnly(ctx, c.req.raw);
    const approval = requireApproval(ctx, c.req.param("id"), claims);
    return c.json({
      approval_id: approval.id,
      status: approval.status,
      expires_at: approval.expiresAt,
    });
  });

  app.post("/approvals/:id/execute", async (c) => {
    const approvalId = c.req.param("id");
    const { claims, grant } = await authenticate(
      ctx,
      c.req.raw,
      `/v1/gate/approvals/${approvalId}/execute`,
    );
    const approval = requireApproval(ctx, approvalId, claims);

    if (approval.status === "pending") {
      throw new ToolgateError(ErrorCodes.APPROVAL_PENDING, "approval still pending");
    }
    if (approval.status !== "approved") {
      throw new ToolgateError(ErrorCodes.APPROVAL_DENIED, `approval is ${approval.status}`);
    }
    if (new Date(approval.expiresAt).getTime() < Date.now()) {
      approval.status = "expired";
      ctx.store.putApproval(approval);
      throw new ToolgateError(ErrorCodes.APPROVAL_DENIED, "approval expired before execution");
    }

    const { upstream, toolDef } = resolveTool(ctx, claims.tenant, approval.upstream, approval.tool);
    // The stored args are the approved args — the agent cannot substitute them.
    const auditBase = {
      id: newId("evt"),
      tenantId: claims.tenant,
      ts: new Date().toISOString(),
      actor: {
        agentId: claims.act.sub,
        userId: claims.sub,
        grantId: grant.id,
        tokenJti: claims.jti,
      },
      action: {
        callId: approval.callId,
        upstream: approval.upstream,
        tool: approval.tool,
        argsHash: hashArgs(approval.args),
      },
    };
    const decision: AuditDecision = {
      effect: "allow",
      source: "approval",
      reason: `approved by ${approval.decidedBy ?? "unknown"} at ${approval.decidedAt ?? "?"}`,
    };

    const result = await executeCall(ctx, {
      auditBase,
      decision,
      grant,
      upstream,
      toolDef,
      tool: approval.tool,
      args: approval.args,
    });

    approval.status = "executed";
    approval.executedAt = new Date().toISOString();
    ctx.store.putApproval(approval);
    return c.json({ status: "executed", call_id: approval.callId, result });
  });

  return app;
}

// ---------------------------------------------------------------------------
// Pipeline stages
// ---------------------------------------------------------------------------

async function authenticateTokenOnly(ctx: AppContext, req: Request): Promise<AuthedCall> {
  const auth = req.headers.get("authorization") ?? "";
  if (!auth.toLowerCase().startsWith("bearer ")) {
    throw new ToolgateError(ErrorCodes.TOKEN_INVALID, "missing bearer capability token");
  }
  const token = auth.slice(7).trim();
  const claims = await verifyCapabilityToken(ctx.keys.control.publicJwk, token, {
    issuer: ctx.config.issuer,
    audience: ctx.config.gateAudience,
  });

  const grant = ctx.store.getGrant(claims.grant_id);
  if (!grant) throw new ToolgateError(ErrorCodes.NOT_FOUND, "grant no longer exists");
  if (grant.status !== "active") {
    // Live tokens die with their grant: revocation is immediate.
    throw new ToolgateError(ErrorCodes.REVOKED, "grant revoked");
  }
  if (new Date(grant.expiresAt).getTime() < Date.now()) {
    throw new ToolgateError(ErrorCodes.TOKEN_EXPIRED, "grant expired");
  }
  const agent = ctx.store.getAgent(claims.act.sub);
  if (!agent || agent.status !== "active") {
    throw new ToolgateError(ErrorCodes.REVOKED, "agent unknown or disabled");
  }
  return { claims, grant };
}

async function authenticate(ctx: AppContext, req: Request, path: string): Promise<AuthedCall> {
  const authed = await authenticateTokenOnly(ctx, req);
  const proof = req.headers.get("x-toolgate-proof");
  if (!proof) throw new ToolgateError(ErrorCodes.PROOF_INVALID, "missing x-toolgate-proof header");

  const token = (req.headers.get("authorization") ?? "").slice(7).trim();
  const verified = await verifyPopProof(proof, {
    expectedJkt: authed.claims.cnf.jkt,
    htm: req.method,
    htu: `${ctx.config.publicUrl}${path}`,
    accessToken: token,
  });
  if (!ctx.store.consumeJti(verified.jti, "proof", 120)) {
    throw new ToolgateError(ErrorCodes.PROOF_INVALID, "proof replayed");
  }
  return authed;
}

function resolveTool(
  ctx: AppContext,
  tenantId: string,
  upstreamName: string,
  tool: string,
): { upstream: Upstream; toolDef: ToolDef } {
  const upstream = ctx.store.findUpstreamByName(tenantId, upstreamName);
  if (!upstream) throw new ToolgateError(ErrorCodes.NOT_FOUND, `unknown upstream: ${upstreamName}`);
  const toolDef = upstream.tools.find((t) => t.name === tool);
  if (!toolDef) {
    throw new ToolgateError(ErrorCodes.NOT_FOUND, `unknown tool ${tool} on upstream ${upstreamName}`);
  }
  return { upstream, toolDef };
}

function requireApproval(
  ctx: AppContext,
  approvalId: string,
  claims: CapabilityClaims,
): ApprovalRequest {
  const approval = ctx.store.getApproval(approvalId);
  if (!approval) throw new ToolgateError(ErrorCodes.NOT_FOUND, `approval not found: ${approvalId}`);
  if (approval.grantId !== claims.grant_id || approval.tenantId !== claims.tenant) {
    throw new ToolgateError(ErrorCodes.DENIED, "approval belongs to a different grant");
  }
  return approval;
}

interface ExecuteOptions {
  auditBase: {
    id: string;
    tenantId: string;
    ts: string;
    actor: { agentId: string; userId: string; grantId: string; tokenJti: string };
    action: { callId: string; upstream: string; tool: string; argsHash: string };
  };
  decision: AuditDecision;
  grant: DelegationGrant;
  upstream: Upstream;
  toolDef: ToolDef;
  tool: string;
  args: Record<string, unknown>;
}

async function executeCall(ctx: AppContext, o: ExecuteOptions): Promise<unknown> {
  if (!ctx.store.chargeBudget(o.grant.id, o.toolDef.costUnits)) {
    ctx.audit.record({
      ...o.auditBase,
      decision: {
        effect: "deny",
        source: "budget",
        reason: `budget exhausted (cost ${o.toolDef.costUnits})`,
      },
      result: { status: "denied" },
    });
    throw new ToolgateError(ErrorCodes.BUDGET_EXCEEDED, "delegation grant budget exhausted", {
      costUnits: o.toolDef.costUnits,
    });
  }

  const sealed = ctx.store.getSecret(o.upstream.credential.secretRef);
  if (!sealed) throw new ToolgateError(ErrorCodes.INTERNAL, "upstream credential missing from vault");
  const secret = ctx.vault.open(sealed);

  const url = new URL(`${o.upstream.baseUrl.replace(/\/$/, "")}/tools/${o.tool}`);
  const headers: Record<string, string> = { "content-type": "application/json" };
  const cred = o.upstream.credential;
  if (cred.mode === "bearer") headers.authorization = `Bearer ${secret}`;
  else if (cred.mode === "header") headers[cred.headerName.toLowerCase()] = secret;
  else url.searchParams.set(cred.paramName, secret);

  const started = Date.now();
  let response: Response;
  try {
    response = await ctx.fetchImpl(url, {
      method: "POST",
      headers,
      body: JSON.stringify(o.args),
    });
  } catch (err) {
    ctx.audit.record({
      ...o.auditBase,
      decision: o.decision,
      result: { status: "error", latencyMs: Date.now() - started },
    });
    const message = err instanceof Error ? err.message : String(err);
    throw new ToolgateError(ErrorCodes.UPSTREAM_ERROR, `upstream unreachable: ${message}`);
  }

  const latencyMs = Date.now() - started;
  const body: unknown = await response.json().catch(() => ({ raw: "non-JSON upstream response" }));

  if (!response.ok) {
    ctx.audit.record({
      ...o.auditBase,
      decision: o.decision,
      result: { status: "error", httpStatus: response.status, latencyMs },
    });
    throw new ToolgateError(ErrorCodes.UPSTREAM_ERROR, `upstream returned ${response.status}`);
  }

  ctx.audit.record({
    ...o.auditBase,
    decision: o.decision,
    result: {
      status: "executed",
      httpStatus: response.status,
      latencyMs,
      costUnits: o.toolDef.costUnits,
    },
  });
  return body;
}

function toAuditDecision(d: {
  effect: "allow" | "deny" | "require_approval";
  source: "token_bounds" | "rule" | "constraint" | "budget" | "default";
  reason: string;
  ruleId?: string;
}): AuditDecision {
  return {
    effect: d.effect,
    source: d.source,
    reason: d.reason,
    ...(d.ruleId ? { ruleId: d.ruleId } : {}),
  };
}
