# Toolgate Architecture

Toolgate is a **capability control plane for embedded AI agents**. It exists because of one design commitment, validated by the September 2026 standards and incident landscape:

> **The agent never holds credentials. Not the user's, not the tenant's, not anyone's.**

Agents hold exactly two things: their own Ed25519 keypair (their identity) and short-lived capability tokens that are useless without that keypair. Real credentials live in the control plane's vault and are injected server-side at the moment of execution.

## Why this design (research summary)

Every marquee agent-security incident of 2025–2026 (EchoLeak, GitHub MCP, Supabase MCP, ForcedLeak, ShadowPrompt) shares one root cause: an agent wielding a credential far broader than its task. The industry consensus — IETF drafts (RFC 8693 token exchange, WIMSE, draft-klrc-aiagent-auth), the MCP 2026-07-28 authorization spec (which outright bans token passthrough), and every hyperscaler implementation (Entra Agent ID, AWS AgentCore Identity, Google GEAP, Auth0 for GenAI) — landed on the same shape:

1. **Agents are first-class identities**, not extensions of the user (impersonation breaks audit, revocation, and attribution).
2. **User authority flows through explicit delegation grants**, never through the user's own token.
3. **Execution uses per-task capability tokens**: audience-bound, minutes-long, sender-constrained, carrying the delegated authority as structured claims.

See `docs/adr/` for the individual decisions.

## System components

```
┌────────────┐   1. client assertion + grant ref    ┌─────────────────────────┐
│            │ ────────────────────────────────────▶│  CONTROL PLANE          │
│   Agent    │ ◀──────────────────────────────────── │  /v1/token (exchange)   │
│ (embedded, │   2. capability token (120s, PoP)     │  grants, policies,      │
│  no creds) │                                       │  approvals, revocation  │
│            │   3. tool call + token + PoP proof    ├─────────────────────────┤
│            │ ────────────────────────────────────▶│  GATE                   │
│            │ ◀──────────────────────────────────── │  verify → decide →      │
└────────────┘   6. result (or denial / pending)     │  inject creds → execute │
                                                     │  → meter → audit        │
                                                     └───────────┬─────────────┘
                                                    4. call with │ real credential
                                                                 ▼
                                                     ┌─────────────────────────┐
                                                     │  UPSTREAM TOOL BACKEND  │
                                                     │  (CRM, email, API...)   │
                                                     └─────────────────────────┘
```

### Control plane
Registry of tenants, users, agents (public keys only), upstreams, and policies. Issues **delegation grants** (a user's durable, bounded delegation to an agent: which tools, what budget, until when) and exchanges agent client assertions + grant references for **capability tokens**. Owns approvals and revocation.

### Gate
The enforcement choke point. For every tool call it runs the pipeline:

1. **Verify** capability token (signature, audience, expiry, revocation) and the one-time PoP proof (key must match `cnf.jkt`; `jti` single-use; bound to method, URL, and token hash).
2. **Decide**: token `authorization_details` bound what is reachable; the grant's policy decides allow / deny / require_approval; argument constraints are evaluated against the actual call args.
3. **Budget**: charge the call's cost units against the grant budget atomically; refuse when exhausted.
4. **Inject**: fetch the upstream credential from the vault and attach it (bearer/header/query). The credential never appears in any response, log, or token.
5. **Execute** against the upstream and relay the result.
6. **Audit**: append a hash-chained, Ed25519-signed record (who, what, decision, result, args hash — not args).

### Vault
Encrypted-at-rest secret store keyed by `secretRef`. MVP: AES-256-GCM with a master key from environment; production path: KMS envelope encryption.

### Approvals (human-in-the-loop)
When policy says `require_approval`, the gate parks the call and returns `202` with an approval id. The user (or an operator) approves or denies **the exact call** — approval is bound to the argument hash, so the agent cannot swap arguments after approval. The agent polls (SDK helper) and the gate executes on approval. This is the CIBA pattern adapted to tool calls.

## Token design

Capability token (EdDSA JWT, typ `tg+jwt`), aligned with RFC 8693 / 9396 / 7800:

| Claim | Meaning |
| --- | --- |
| `iss` / `aud` | control plane issuer / the gate |
| `sub` | **the human principal** the work is for |
| `act.sub` | **the agent** actually acting (delegation, not impersonation) |
| `tenant`, `grant_id` | tenancy + the durable grant this token was minted from |
| `scope` | coarse OAuth-style scopes (space-delimited) — **advisory metadata only; not independently enforced at the gate** |
| `authorization_details` | RFC 9396-style: exactly which upstreams/tools are reachable — **the authoritative enforcement bound** |
| `cnf.jkt` | thumbprint of the agent key that must sign per-call PoP proofs |
| `txn` | per-task transaction id — the audit join key |
| `exp` | short TTL (default 120s) with ±15% jitter |
| `jti` | unique id; revocable |

Security properties: a stolen token is inert (PoP), a stolen token+key pair is bounded (authorization_details ∩ policy ∩ budget ∩ TTL), and everything an agent ever did is attributable (`sub` vs `act.sub` vs `txn` in every audit record).

## Data model

`Tenant → Users, Agents (pubkey), Upstreams (tools + credential ref), Policies (ordered rules)`
`DelegationGrant = (user, agent, authorization[], budget, policy, expiry, status)`
`ApprovalRequest = parked call bound to args hash`
`AuditRecord = hash-chained, signed; verifiable as a chain`

Persistence: SQLite (stdlib `sqlite3`) behind a thin store interface — swap for Postgres without touching domain logic. Runtime: Python/FastAPI (ADR 0005; originally Node/Hono per ADR 0003).

## Threat model (abridged)

| Threat | Mitigation |
| --- | --- |
| Token exfiltration from embedded agent | PoP binding (`cnf.jkt` + one-time proofs), short jittered TTL |
| Prompt-injected confused deputy | authorization_details bounds + policy arg constraints + approval gates on side-effecting tools |
| Argument swap after approval | approval bound to canonical args hash |
| Replay | proof `jti` single-use, `htu`/`htm`/`ath` binding, token `jti` tracking |
| Audit tampering / cover-up | hash chain + Ed25519 signatures; verification detects edit, removal, reorder |
| Credential leakage | credentials only in vault, injected server-side, never logged, never in tokens |
| Budget runaway | per-grant cost accounting enforced atomically at the gate |

## Non-goals (MVP)

Upstream OAuth token brokering (Arcade-style third-party OAuth), multi-region, Merkle checkpoint anchoring (Rekor/Tessera), WIMSE WIT/WPT credentials, AuthZEN PDP interface — all tracked as post-MVP issues.
