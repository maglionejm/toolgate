# Toolgate

**The capability control plane for embedded AI agents.**

Agents should never hold credentials — not the user's OAuth token, not a tenant API key, not anything. Toolgate sits between agents and the tools they call:

- the agent authenticates with **its own Ed25519 key** and a **delegation grant** from a human;
- it receives **short-lived capability tokens** (`sub` = the human, `act.sub` = the agent, RFC 8693 semantics) that are useless if stolen (proof-of-possession bound);
- every tool call is **policy-checked** (allow / deny / require human approval), **metered** against the grant's budget, and executed by the gate, which **injects the real credential server-side**;
- every decision — including denials — lands in a **hash-chained, Ed25519-signed audit trail**.

```
Agent (no secrets) ── token + one-time proof ──▶ GATE ── real credential ──▶ Upstream API
                                                  │
                                    verify → decide → budget → inject → execute → audit
```

## Try it

```bash
pnpm install
pnpm demo
```

The demo boots Toolgate plus two credential-guarded mock APIs and runs a six-act scenario: an allowed CRM read (upstream rejects anything without its live key — proving injection), a policy denial, an external email parked for human approval and executed against the approved args only, budget exhaustion, revocation that kills a live token instantly, and audit chain verification with the full decision trace.

```
[OK      ] read_contact executed -> {"contact":{...}}
[DENIED  ] TG_DENIED: matched deny rule never-delete
[PARKED  ] approval apr_... pending — agent is blocked, not trusted
[HUMAN   ] Sam approved the exact parked arguments (args are hash-bound)
[OK      ] send_email executed after approval
[BUDGET  ] blocked: delegation grant budget exhausted
[REVOKED ] TG_REVOKED: live token died with the grant, no TTL wait
[AUDIT   ] chain of 10 records — verification: VALID
```

## How it works

1. **Register** a tenant, its users, agents (public keys only), and upstreams. Upstream credentials are sealed into the vault (AES-256-GCM) and never leave the server.
2. **Delegate**: a user grants an agent bounded authority — which upstreams/tools (RFC 9396-style `authorization_details`), what budget (cost units), which policy, until when.
3. **Exchange**: the agent presents a signed client assertion (RFC 7523 style) and receives a capability token — TTL ~2 minutes with jitter, audience-bound, sender-constrained via `cnf.jkt`.
4. **Call**: each gate call carries the token plus a one-time DPoP-style proof signed by the agent key (bound to method, URL, and token hash; replays rejected).
5. **Enforce**: token bounds → policy rules (first match wins, glob matching, dot-path argument constraints, cost ceilings) → default deny → atomic budget charge.
6. **Approve**: `require_approval` parks the call; a human decides on the exact argument set (hash-bound — no post-approval swaps); the agent polls and executes.
7. **Audit**: every decision appends to a hash chain signed by the gate key. `GET /v1/control/audit/verify` proves nothing was edited, removed, or reordered.

## Agent-side SDK

```ts
import { ToolgateClient, generateEd25519KeyPair } from "@toolgate/sdk";

const client = new ToolgateClient({ baseUrl, agentId, agentPrivateJwk, grantId });

const res = await client.call("crm", "read_contact", { contactId: "c-001" });
if (res.status === "pending_approval") {
  const executed = await client.waitForApproval(res.approvalId);
}
// Denials, budget exhaustion, and revocation throw typed ToolgateCallError
// (TG_DENIED / TG_BUDGET_EXCEEDED / TG_REVOKED / TG_PROOF_INVALID / ...).
```

## Packages

| Package | Purpose |
| --- | --- |
| `@toolgate/core` | Capability tokens, client assertions + PoP proofs, policy engine, audit chain |
| `@toolgate/server` | Control plane (registry, grants, token endpoint, approvals, revocation, audit) + gate (enforcement pipeline, vault) |
| `@toolgate/sdk` | Agent-side client: token exchange, signed calls, approval flow, typed errors |
| `@toolgate/demo` | End-to-end scenario (`pnpm demo`) |

## Design

- `docs/ARCHITECTURE.md` — components, token design, threat model
- `docs/adr/0001` — delegation, never user-credential impersonation
- `docs/adr/0002` — JWT on OAuth rails (RFC 8693/9396/7800) over Biscuit/Macaroon/UCAN
- `docs/adr/0003` — Node 26 + Hono + `node:sqlite`, internal-packages monorepo
- `docs/adr/0004` — approvals bound to args hashes; hash-chained signed audit

Roadmap lives in the [issue tracker](../../issues): MCP compatibility, upstream OAuth brokering, Merkle checkpoint anchoring, approvals via Slack/webhooks/CIBA push, dashboard, Postgres scale-out, Python SDK.

## Development

```bash
pnpm install
pnpm typecheck   # strict TS across all packages
pnpm test        # 39 tests: unit (core) + integration (server) + SDK-vs-server
pnpm demo        # the six-act scenario
```

Server entry: `pnpm --filter @toolgate/server start` (prints the admin key on first boot; set `TOOLGATE_MASTER_KEY`, `TOOLGATE_ADMIN_KEY`, `TOOLGATE_PUBLIC_URL`, `TOOLGATE_DB` in production).
