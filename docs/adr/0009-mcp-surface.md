# ADR 0009: MCP surface with a deliberate PoP exemption

**Status**: accepted · 2026-09-12

## Context

MCP is the distribution wedge: any MCP client can consume gated tools by pasting a URL. But MCP clients cannot produce Toolgate PoP proofs, and the MCP authorization model is plain OAuth bearer at the resource server.

## Decision

`POST /v1/mcp` (JSON-RPC 2.0, Streamable HTTP shape) authenticates with the bearer capability token only. Everything below authentication is unchanged — the same `run_gate_call` pipeline (bounds → taint-aware policy → budget → inject → execute → audit) serves REST and MCP. `tools/list` is bounded by the token's `authorization_details`; approvals surface as retryable `-32009` errors carrying the approval id; denials as `-32010` with the Toolgate error envelope. Deployments that refuse the sender-binding trade set `mcp_enabled=False`.

## Consequences

A stolen token used via MCP is *not* inert (no `cnf` proof) — the compensating controls are the short jittered TTL, audience binding, instant grant revocation, budgets, and full auditing. Recommend minting MCP-bound grants with tighter budgets/TTLs. Proof-capable MCP transport is worth revisiting if the MCP spec grows sender-constrained tokens.
