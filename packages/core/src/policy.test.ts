import { describe, expect, it } from "vitest";
import { checkBudget, decide, evaluatePolicy, globMatch } from "./policy.js";
import type { AuthorizationDetail, Policy } from "./types.js";

const POLICY: Policy = {
  id: "pol_1",
  tenantId: "tnt_1",
  name: "test policy",
  createdAt: new Date().toISOString(),
  rules: [
    {
      id: "deny-bulk-delete",
      effect: "deny",
      match: { upstream: "crm", tool: "delete_*" },
    },
    {
      id: "approve-external-email",
      effect: "require_approval",
      match: {
        upstream: "email",
        tool: "send_email",
        where: [{ path: "to", op: "matches", value: "@(?!acme\\.com)" }],
      },
    },
    {
      id: "allow-internal-email",
      effect: "allow",
      match: { upstream: "email", tool: "send_email" },
    },
    {
      id: "allow-crm-reads",
      effect: "allow",
      match: { upstream: "crm", tool: "*" },
      constraints: { maxCostUnits: 5 },
    },
  ],
};

const AUTHZ: AuthorizationDetail[] = [
  { type: "toolgate:tool_call", upstream: "crm", tools: ["*"] },
  { type: "toolgate:tool_call", upstream: "email", tools: ["send_email"] },
];

describe("policy engine", () => {
  it("default-denies when nothing matches", () => {
    const d = evaluatePolicy(POLICY, {
      upstream: "billing",
      tool: "charge",
      args: {},
      costUnits: 1,
    });
    expect(d).toMatchObject({ effect: "deny", source: "default" });
  });

  it("first matching rule wins (deny before broad allow)", () => {
    const d = evaluatePolicy(POLICY, {
      upstream: "crm",
      tool: "delete_contact",
      args: {},
      costUnits: 1,
    });
    expect(d).toMatchObject({ effect: "deny", ruleId: "deny-bulk-delete" });
  });

  it("allows reads under the cost ceiling", () => {
    const d = evaluatePolicy(POLICY, {
      upstream: "crm",
      tool: "list_contacts",
      args: {},
      costUnits: 3,
    });
    expect(d).toMatchObject({ effect: "allow", ruleId: "allow-crm-reads" });
  });

  it("denies when call cost exceeds the rule ceiling", () => {
    const d = evaluatePolicy(POLICY, {
      upstream: "crm",
      tool: "export_all",
      args: {},
      costUnits: 50,
    });
    expect(d).toMatchObject({ effect: "deny", source: "constraint" });
  });

  it("routes external email to approval via arg constraint, internal to allow", () => {
    const external = evaluatePolicy(POLICY, {
      upstream: "email",
      tool: "send_email",
      args: { to: "ceo@bigcorp.com" },
      costUnits: 1,
    });
    expect(external).toMatchObject({ effect: "require_approval", ruleId: "approve-external-email" });

    const internal = evaluatePolicy(POLICY, {
      upstream: "email",
      tool: "send_email",
      args: { to: "sam@acme.com" },
      costUnits: 1,
    });
    expect(internal).toMatchObject({ effect: "allow", ruleId: "allow-internal-email" });
  });

  it("token authorization_details bound the reachable surface before policy", () => {
    const d = decide(
      POLICY,
      { upstream: "email", tool: "delete_mailbox", args: {}, costUnits: 1 },
      AUTHZ,
    );
    expect(d).toMatchObject({ effect: "deny", source: "token_bounds" });
  });

  it("permits calls inside token bounds and policy", () => {
    const d = decide(
      POLICY,
      { upstream: "crm", tool: "read_contact", args: {}, costUnits: 1 },
      AUTHZ,
    );
    expect(d.effect).toBe("allow");
  });
});

describe("globMatch", () => {
  it("matches literals, wildcards and prefixes", () => {
    expect(globMatch("*", "anything")).toBe(true);
    expect(globMatch("crm", "crm")).toBe(true);
    expect(globMatch("crm", "crm2")).toBe(false);
    expect(globMatch("delete_*", "delete_contact")).toBe(true);
    expect(globMatch("delete_*", "read_contact")).toBe(false);
  });
});

describe("checkBudget", () => {
  it("tracks remaining units", () => {
    expect(checkBudget({ maxUnits: 10, spentUnits: 7 }, 3)).toEqual({
      ok: true,
      remainingUnits: 3,
    });
    expect(checkBudget({ maxUnits: 10, spentUnits: 7 }, 4)).toEqual({
      ok: false,
      remainingUnits: 3,
    });
  });
});
