# ADR 0001: Agents get delegation, never the user's credentials

**Status**: accepted · 2026-09-02

## Context

The central design question: when an agent acts for a human, does it (a) use the human's own OAuth token/session (impersonation), (b) act under its own identity with an explicit delegation grant, or (c) receive per-task capability tokens?

Research findings (Sept 2026):
- RFC 8693 distinguishes impersonation ("A *is* B") from delegation (`sub`=user + `act`=agent, both identities preserved). Every 2025–2026 incident postmortem (EchoLeak CVE-2025-32711, GitHub MCP, Supabase MCP service_role, ForcedLeak, ShadowPrompt) indicts ambient over-broad credentials.
- Impersonation failure modes are documented across Red Hat, Okta, WorkOS, OIDF AIIM: audit trails collapse into one identity, no per-agent revocation, scope ≫ task intent, decision attribution lost.
- The hyperscalers all converged on first-class agent identity with dual autonomous/delegated modes (Entra Agent ID directory objects, AWS AgentCore workload identity, Google GEAP SPIFFE-ID-as-IAM-principal).
- MCP authorization spec 2026-07-28 **forbids token passthrough** outright.
- draft-klrc-aiagent-auth: "Every agent MUST have exactly one WIMSE identifier."

## Decision

Model (b) as the skeleton with model (c) semantics on top:
1. Every agent has a first-class identity: an Ed25519 keypair; only the public key is registered.
2. User authority is conveyed by a **delegation grant** (durable record: tools, budget, policy, expiry) — never by the user's token.
3. Execution uses **per-task capability tokens** minted from grants: `sub`=user, `act.sub`=agent, RFC 9396 `authorization_details`, `cnf.jkt` sender-binding, short jittered TTL.
4. Real upstream credentials live only in the control-plane vault and are injected at execution time.

## Consequences

- Independent revocation at three grains: agent identity, grant, token `jti`.
- Every audit record distinguishes *who authorized* (`sub`) from *who acted* (`act.sub`).
- The agent-side SDK never touches secrets, so it is safe to embed client-side (browser/WASM harnesses).
- Cost: Toolgate must run a token endpoint and the gate becomes a hard dependency in the call path (mitigated by short-TTL local verification at the gate — no DB hit for signature checks).
