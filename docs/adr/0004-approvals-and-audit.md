# ADR 0004: Approvals bound to argument hashes; audit as a signed hash chain

**Status**: accepted · 2026-09-02

## Context

Human-in-the-loop: per-action prompting causes approval fatigue (Anthropic telemetry: 93% blanket approval; OWASP T10 "Overwhelming the Human in the Loop"). The 2026 norm is risk-tiered approval, async where needed (CIBA pattern), with consent naming the exact action — and WorkOS's pattern of binding the approval to the exact tool arguments.

Audit: EU AI Act Art 12/26(6) requires automatic event recording retained ≥6 months under deployer control; OWASP Agentic Top 10 2026 demands immutable signed logs of all agent actions. AWS QLDB is dead; the converged pattern is hash-chained rows + periodic signed checkpoints + optional external anchoring.

## Decision

1. **Approvals**: policy effect `require_approval` parks the call as an `ApprovalRequest` carrying the canonical args hash. Decisions apply to that hash only — an agent cannot get "send email" approved and then change the recipient. Agent-side UX is poll-based (SDK helper) in the MVP; webhook/push post-MVP. Approvals expire.
2. **Audit**: every gate decision (including denials) appends a record: `seq`, `prevHash`, actor (`agentId`, `userId`, `grantId`, `tokenJti`), action (`callId`, upstream, tool, `argsHash`), decision (effect, source, rule), result (status, latency, cost). The record hash covers all of it; the hash is Ed25519-signed by the gate key. `verifyAuditChain` detects edits, deletions, reordering, and foreign signatures. Args themselves are not stored (privacy) — only their hash (provability).

## Consequences

- The audit log is the product's compliance artifact (AI Act Art 26(6)-ready; exportable).
- Post-MVP: periodic Merkle checkpoints anchored to Sigstore Rekor/Tessera for external verifiability (backlog).
