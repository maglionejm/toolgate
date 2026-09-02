import { Hono } from "hono";
import { z } from "zod";
import {
  AuthorizationDetailSchema,
  ErrorCodes,
  PolicyRuleSchema,
  ToolDefSchema,
  ToolgateError,
  jwkThumbprint,
  mintCapabilityToken,
  newId,
  verifyClientAssertion,
  type AgentIdentity,
  type ApprovalRequest,
  type DelegationGrant,
  type Policy,
  type Tenant,
  type Upstream,
  type User,
} from "@toolgate/core";
import type { AppContext } from "./context.js";

const CreateTenantSchema = z.object({ name: z.string().min(1) });
const CreateUserSchema = z.object({
  tenantId: z.string(),
  displayName: z.string().min(1),
  email: z.email().optional(),
});
const CreateAgentSchema = z.object({
  tenantId: z.string(),
  name: z.string().min(1),
  publicJwk: z.record(z.string(), z.unknown()),
});
const CreateUpstreamSchema = z.object({
  tenantId: z.string(),
  name: z.string().min(1),
  baseUrl: z.url(),
  credential: z.discriminatedUnion("mode", [
    z.object({ mode: z.literal("bearer"), secret: z.string().min(1) }),
    z.object({ mode: z.literal("header"), headerName: z.string().min(1), secret: z.string().min(1) }),
    z.object({ mode: z.literal("query"), paramName: z.string().min(1), secret: z.string().min(1) }),
  ]),
  tools: z.array(ToolDefSchema).min(1),
});
const CreatePolicySchema = z.object({
  tenantId: z.string(),
  name: z.string().min(1),
  rules: z.array(PolicyRuleSchema),
});
const CreateGrantSchema = z.object({
  tenantId: z.string(),
  userId: z.string(),
  agentId: z.string(),
  policyId: z.string(),
  scopes: z.array(z.string()).default([]),
  authorization: z.array(AuthorizationDetailSchema).min(1),
  budgetMaxUnits: z.number().int().positive(),
  ttlHours: z.number().positive().default(24),
});
const DecideApprovalSchema = z.object({
  decision: z.enum(["approve", "deny"]),
  decidedBy: z.string().min(1),
});
const TokenRequestSchema = z.object({
  grant_type: z.literal("urn:ietf:params:oauth:grant-type:token-exchange"),
  client_assertion: z.string().min(1),
  grant_id: z.string().min(1),
  requested_ttl_seconds: z.number().int().positive().optional(),
});

async function parseBody<T>(c: { req: { json(): Promise<unknown> } }, schema: z.ZodType<T>): Promise<T> {
  let raw: unknown;
  try {
    raw = await c.req.json();
  } catch {
    throw new ToolgateError(ErrorCodes.VALIDATION, "request body must be JSON");
  }
  const parsed = schema.safeParse(raw);
  if (!parsed.success) {
    throw new ToolgateError(ErrorCodes.VALIDATION, "invalid request body", {
      issues: parsed.error.issues.map((i) => `${i.path.join(".")}: ${i.message}`),
    });
  }
  return parsed.data;
}

export function controlRoutes(ctx: AppContext): Hono {
  const app = new Hono();
  const now = () => new Date().toISOString();

  // Admin auth for everything under /v1/control.
  app.use("*", async (c, next) => {
    if (c.req.header("x-toolgate-admin-key") !== ctx.config.adminKey) {
      throw new ToolgateError(ErrorCodes.TOKEN_INVALID, "missing or wrong admin key");
    }
    await next();
  });

  app.post("/tenants", async (c) => {
    const body = await parseBody(c, CreateTenantSchema);
    const tenant: Tenant = { id: newId("tnt"), name: body.name, createdAt: now() };
    ctx.store.putTenant(tenant);
    return c.json(tenant, 201);
  });

  app.post("/users", async (c) => {
    const body = await parseBody(c, CreateUserSchema);
    requireTenant(ctx, body.tenantId);
    const user: User = {
      id: newId("usr"),
      tenantId: body.tenantId,
      displayName: body.displayName,
      ...(body.email ? { email: body.email } : {}),
      createdAt: now(),
    };
    ctx.store.putUser(user);
    return c.json(user, 201);
  });

  app.post("/agents", async (c) => {
    const body = await parseBody(c, CreateAgentSchema);
    requireTenant(ctx, body.tenantId);
    const agent: AgentIdentity = {
      id: newId("agt"),
      tenantId: body.tenantId,
      name: body.name,
      publicJwk: body.publicJwk,
      status: "active",
      createdAt: now(),
    };
    ctx.store.putAgent(agent);
    return c.json(agent, 201);
  });

  app.post("/upstreams", async (c) => {
    const body = await parseBody(c, CreateUpstreamSchema);
    requireTenant(ctx, body.tenantId);
    const id = newId("ups");
    const secretRef = `sec_${id}`;
    ctx.store.putSecret(secretRef, ctx.vault.seal(body.credential.secret));
    const { secret: _secret, ...credential } = body.credential;
    const upstream: Upstream = {
      id,
      tenantId: body.tenantId,
      name: body.name,
      baseUrl: body.baseUrl,
      credential: { ...credential, secretRef },
      tools: body.tools,
      createdAt: now(),
    };
    ctx.store.putUpstream(upstream);
    return c.json(upstream, 201);
  });

  app.post("/policies", async (c) => {
    const body = await parseBody(c, CreatePolicySchema);
    requireTenant(ctx, body.tenantId);
    const policy: Policy = {
      id: newId("pol"),
      tenantId: body.tenantId,
      name: body.name,
      rules: body.rules,
      createdAt: now(),
    };
    ctx.store.putPolicy(policy);
    return c.json(policy, 201);
  });

  app.post("/grants", async (c) => {
    const body = await parseBody(c, CreateGrantSchema);
    requireTenant(ctx, body.tenantId);
    if (!ctx.store.getUser(body.userId)) throw notFound("user", body.userId);
    if (!ctx.store.getAgent(body.agentId)) throw notFound("agent", body.agentId);
    if (!ctx.store.getPolicy(body.policyId)) throw notFound("policy", body.policyId);
    const grant: DelegationGrant = {
      id: newId("grt"),
      tenantId: body.tenantId,
      userId: body.userId,
      agentId: body.agentId,
      policyId: body.policyId,
      scopes: body.scopes,
      authorization: body.authorization,
      budget: { maxUnits: body.budgetMaxUnits, spentUnits: 0 },
      expiresAt: new Date(Date.now() + body.ttlHours * 3_600_000).toISOString(),
      status: "active",
      createdAt: now(),
    };
    ctx.store.putGrant(grant);
    return c.json(grant, 201);
  });

  app.post("/grants/:id/revoke", (c) => {
    const grant = ctx.store.getGrant(c.req.param("id"));
    if (!grant) throw notFound("grant", c.req.param("id"));
    grant.status = "revoked";
    ctx.store.putGrant(grant);
    return c.json({ id: grant.id, status: grant.status });
  });

  app.get("/approvals", (c) => {
    const tenantId = c.req.query("tenantId");
    if (!tenantId) throw new ToolgateError(ErrorCodes.VALIDATION, "tenantId query param required");
    const status = c.req.query("status") as ApprovalRequest["status"] | undefined;
    return c.json(ctx.store.listApprovals(tenantId, status));
  });

  app.post("/approvals/:id/decide", async (c) => {
    const body = await parseBody(c, DecideApprovalSchema);
    const approval = ctx.store.getApproval(c.req.param("id"));
    if (!approval) throw notFound("approval", c.req.param("id"));
    if (approval.status !== "pending") {
      throw new ToolgateError(ErrorCodes.VALIDATION, `approval is ${approval.status}, not pending`);
    }
    if (new Date(approval.expiresAt).getTime() < Date.now()) {
      approval.status = "expired";
      ctx.store.putApproval(approval);
      throw new ToolgateError(ErrorCodes.VALIDATION, "approval expired");
    }
    approval.status = body.decision === "approve" ? "approved" : "denied";
    approval.decidedAt = now();
    approval.decidedBy = body.decidedBy;
    ctx.store.putApproval(approval);
    return c.json(approval);
  });

  app.get("/audit", (c) => {
    const tenantId = c.req.query("tenantId");
    return c.json(ctx.store.listAudit(tenantId));
  });

  app.get("/audit/verify", (c) => c.json(ctx.audit.verify()));

  return app;
}

/**
 * Token endpoint (agent-facing, not admin-authed): RFC 8693-style exchange of
 * a client assertion + grant reference for a capability token.
 */
export function tokenRoute(ctx: AppContext): Hono {
  const app = new Hono();

  app.post("/", async (c) => {
    const body = await parseBody(c, TokenRequestSchema);

    const grant = ctx.store.getGrant(body.grant_id);
    if (!grant) throw new ToolgateError(ErrorCodes.NOT_FOUND, "unknown grant");
    if (grant.status !== "active") throw new ToolgateError(ErrorCodes.REVOKED, "grant revoked");
    if (new Date(grant.expiresAt).getTime() < Date.now()) {
      throw new ToolgateError(ErrorCodes.TOKEN_EXPIRED, "grant expired");
    }

    const agent = ctx.store.getAgent(grant.agentId);
    if (!agent || agent.status !== "active") {
      throw new ToolgateError(ErrorCodes.REVOKED, "agent unknown or disabled");
    }

    const tokenUrl = `${ctx.config.issuer}/v1/token`;
    const assertion = await verifyClientAssertion(agent.publicJwk, body.client_assertion, {
      expectedAudience: tokenUrl,
    });
    if (assertion.agentId !== grant.agentId) {
      throw new ToolgateError(ErrorCodes.TOKEN_INVALID, "assertion is not from the granted agent");
    }
    if (!ctx.store.consumeJti(assertion.jti, "assertion", 300)) {
      throw new ToolgateError(ErrorCodes.TOKEN_INVALID, "client assertion replayed");
    }

    const ttl = Math.min(
      body.requested_ttl_seconds ?? ctx.config.tokenTtlSeconds,
      ctx.config.maxTokenTtlSeconds,
    );
    const { token, jti, txn, expiresAt } = await mintCapabilityToken(ctx.keys.control.privateJwk, {
      issuer: ctx.config.issuer,
      audience: ctx.config.gateAudience,
      tenantId: grant.tenantId,
      userId: grant.userId,
      agentId: grant.agentId,
      grantId: grant.id,
      scopes: grant.scopes,
      authorizationDetails: grant.authorization,
      agentJkt: await jwkThumbprint(agent.publicJwk),
      ttlSeconds: ttl,
    });

    return c.json({
      access_token: token,
      token_type: "Bearer",
      issued_token_type: "urn:ietf:params:oauth:token-type:access_token",
      expires_in: Math.max(1, Math.round((expiresAt.getTime() - Date.now()) / 1000)),
      jti,
      txn,
    });
  });

  return app;
}

function requireTenant(ctx: AppContext, tenantId: string): void {
  if (!ctx.store.getTenant(tenantId)) throw notFound("tenant", tenantId);
}

function notFound(kind: string, id: string): ToolgateError {
  return new ToolgateError(ErrorCodes.NOT_FOUND, `${kind} not found: ${id}`);
}
