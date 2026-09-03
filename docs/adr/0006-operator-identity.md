# ADR 0006: Operator identity replaces the shared admin key

**Status**: accepted · 2026-09-12

## Context

Agents were perfectly attributed while every admin action hid behind one static header — indefensible for a product whose pitch is attribution. Passkeys/OIDC are the eventual answer but need session infrastructure.

## Decision

Operators are first-class principals with per-operator keys (`opk_`, SHA-256-hashed at rest, plaintext shown exactly once) and three roles: `auditor` (read), `approver` (read + approval decisions), `owner` (all mutations). Every control-plane mutation appends an audit record (`actor.agentId="control-plane"`, `actor.userId=<operator>`, `decision.source="operator"`). The static admin key survives only as a **break-glass** path, attributed as `op_breakglass`. Approval `decidedBy` defaults to the authenticated operator — no more self-reported identity.

## Consequences

The signed chain now covers *everyone*: agents, humans-in-the-loop, and operators. Passkey/OIDC login and per-tenant operator scoping remain future work; key material handling matches agent keys (hash-only storage).
