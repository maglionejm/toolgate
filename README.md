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
uv sync
uv run toolgate-demo
```

The demo boots Toolgate plus two credential-guarded mock APIs and runs a six-act scenario: an allowed CRM read (the upstream rejects anything without its live key — proving injection), a policy denial, an external email parked for human approval and executed against the approved args only, budget exhaustion, revocation that kills a live token instantly, and audit chain verification with the full decision trace.

```
[OK      ] read_contact executed -> {'contact': {...}}
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

```python
from toolgate.sdk import ToolgateClient, PendingApproval, generate_ed25519_key_pair

client = ToolgateClient(
    base_url=base_url,
    agent_id=agent_id,
    agent_private_jwk=agent_private_jwk,  # the only secret an agent ever holds
    grant_id=grant_id,
)

result = client.call("crm", "read_contact", {"contactId": "c-001"})
if isinstance(result, PendingApproval):
    result = client.wait_for_approval(result.approval_id)
# Denials, budget exhaustion, and revocation raise typed ToolgateCallError
# (TG_DENIED / TG_BUDGET_EXCEEDED / TG_REVOKED / TG_PROOF_INVALID / ...).
```

## Layout

| Module | Purpose |
| --- | --- |
| `toolgate.core` | Capability tokens, client assertions + PoP proofs, policy engine, audit chain |
| `toolgate.server` | Control plane (registry, grants, token endpoint, approvals, revocation, audit) + gate (enforcement pipeline, vault) |
| `toolgate.sdk` | Agent-side client: token exchange, signed calls, approval flow, typed errors |
| `toolgate.demo` | End-to-end scenario (`uv run toolgate-demo`) |

## Documentation

Full suite in [`docs/`](docs/README.md): [Quickstart](docs/QUICKSTART.md) · [API Reference](docs/reference/API.md) · [Token Spec](docs/TOKEN-SPEC.md) · [Security Model](docs/SECURITY.md) · [Deployment](docs/DEPLOYMENT.md) · [Operations](docs/OPERATIONS.md)

## Design

- `docs/ARCHITECTURE.md` — components, token design, threat model
- `docs/adr/0001` — delegation, never user-credential impersonation
- `docs/adr/0002` — JWT on OAuth rails (RFC 8693/9396/7800) over Biscuit/Macaroon/UCAN
- `docs/adr/0003` — original TS runtime decision (superseded by 0005)
- `docs/adr/0004` — approvals bound to args hashes; hash-chained signed audit
- `docs/adr/0005` — Python as the reference implementation

Roadmap lives in the [issue tracker](../../issues): MCP compatibility, upstream OAuth brokering, Merkle checkpoint anchoring, approvals via Slack/webhooks/CIBA push, dashboard, Postgres scale-out, TypeScript SDK rebuild.

## Development

```bash
uv sync
uv run ruff check src tests
uv run pytest tests/ -q     # 39 tests: core unit + server integration + SDK-vs-server
uv run toolgate-demo        # the six-act scenario
uv run toolgate-server      # standalone server (prints the admin key on first boot)
```

Production env vars: `TOOLGATE_MASTER_KEY`, `TOOLGATE_ADMIN_KEY`, `TOOLGATE_PUBLIC_URL`, `TOOLGATE_DB`, `PORT`.
