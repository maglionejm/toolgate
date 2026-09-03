# Security Model

> Toolgate 0.3 · Last updated 2026-09-03

## Design commitment

**The agent never holds credentials.** Not the user's session, not an upstream API key, not a shared secret with Toolgate. An agent possesses exactly one secret — its own Ed25519 private key — and everything else it receives is short-lived, narrowly scoped, sender-bound, and revocable.

This is the delegation model (RFC 8693 `sub`=user, `act.sub`=agent) chosen after reviewing the 2025–2026 incident record (EchoLeak, GitHub MCP, Supabase MCP, ForcedLeak, ShadowPrompt — all rooted in agents wielding over-broad ambient credentials) and current standards direction (MCP authorization spec forbids token passthrough; IETF WIMSE/agent-auth drafts require first-class agent identity). See ADR 0001.

## Principals and trust boundaries

| Principal | Holds | Trusts |
| --- | --- | --- |
| Human (user) | Nothing new — approves grants and parked calls | Toolgate's audit trail |
| Agent | Its Ed25519 private key; transient capability tokens | Nothing else — treated as compromised-by-default |
| Control plane | Signing key, vault master key, registry | Operator (admin key) |
| Gate | Audit signing key; enforces everything | Control plane's token signatures |
| Upstream | Its own credential (sealed in the vault) | Calls arriving with that credential |

The **untrusted zone is the agent itself** — including its LLM context. Prompt injection is assumed permanently unsolved; no security property may depend on the model behaving.

## Threat matrix

| # | Threat | Mitigation | Enforced at | Covered by tests |
| --- | --- | --- | --- | --- |
| T1 | Capability token exfiltrated from agent/network | `cnf.jkt` PoP binding: token useless without the agent key | Gate | yes |
| T2 | Token **and** agent key exfiltrated | Blast radius = authorization_details ∩ policy ∩ budget ∩ ≤300s TTL; grant revocation is immediate | Gate | yes |
| T3 | Proof replay | Single-use `jti` store; `htm`/`htu`/`ath` binding; 60s freshness | Gate | yes |
| T4 | Client-assertion replay at token endpoint | Single-use assertion `jti`; 60s TTL; audience = exact token URL | Control plane | yes |
| T5 | Prompt-injected confused deputy (agent calls a tool it shouldn't) | Token bounds checked before policy; default-deny policy; `require_approval` on side-effecting tools | Gate | yes |
| T6 | Argument swap after human approval | Approval bound to the stored argument set; execution uses stored args only; args hash in audit | Gate | yes |
| T7 | Budget runaway / cost-based DoS by agent | Atomic conditional budget charge per call; cost ceilings per rule | Gate + store | yes |
| T8 | Upstream credential leakage | Secrets sealed AES-256-GCM at rest; injected server-side only; never in tokens, responses, or logs | Vault/gate | yes (response scan) |
| T9 | Audit tampering / operator cover-up | Hash chain + Ed25519 signatures; verification detects edit, removal, reorder, foreign key | Audit | yes |
| T10 | Cross-tenant access | Tenant claim in token; upstream/approval/audit lookups tenant-scoped | Gate | partial (see gaps) |
| T11 | Token minted for agent A used by agent B | `cnf.jkt` is A's key thumbprint; B cannot produce proofs | Gate | yes |
| T12 | Approval fatigue as an attack surface (OWASP T10) | Policy tiers: allow routine, approve consequential; budgets cap the rest | Policy design | design-level |

> The T8 "never in tokens, responses, or logs" guarantee covers **upstream credentials**. The **admin key** is a distinct secret — a control-plane bearer credential. As of this release it is no longer printed in plaintext at server boot; only a short fingerprint is logged, so an operator can confirm which key is active without the value ever appearing in logs. Set it explicitly via `TOOLGATE_ADMIN_KEY` and distribute it out-of-band.

## Key management

| Key | Purpose | Storage (MVP) | Production path |
| --- | --- | --- | --- |
| Control-plane Ed25519 | Signs capability tokens | SQLite `settings` (JWK) | KMS/HSM; rotation with overlapping `kid`s |
| Gate Ed25519 | Signs audit records | SQLite `settings` | KMS; periodic Merkle checkpoints anchored externally (issue #12) |
| Vault master key | Seals upstream secrets | `TOOLGATE_MASTER_KEY` env; dev fallback stored alongside data **with a loud warning** | KMS envelope encryption (issue #8) |
| Agent private keys | Client assertions + proofs | Never seen by Toolgate | Agent-side responsibility; recommend OS keychain / secure element |

## The hand-rolled PoP layer

`toolgate/core/assertion.py` implements the RFC 9449-model proof scheme directly because no maintained Python JOSE library ships DPoP (authlib #315, open since 2021). This is the highest-scrutiny surface in the codebase:

- Dedicated tests cover key theft, token rebinding, URL replay, and private-key-in-header rejection.
- The red-team suite (issue #9) targets it first.
- External cryptographic review is a pre-GA requirement.

## Known gaps (tracked, not hidden)

- **Admin plane**: single static admin key (a control-plane bearer credential; logged only as a fingerprint at boot, never in plaintext); no operator identities, no MFA, no rate limiting (issues #24, #21).
- **Tenant isolation** relies on application-level filters over a shared SQLite file; no per-tenant encryption.
- **Vault** master key is env-based; KMS envelope encryption pending (#8).
- **Audit** chain is internally verifiable but not yet externally anchored (#12); a compromised gate key could re-sign a rewritten chain.
- **No dataflow policy**: per-tool allowlists don't stop benign-tool *composition* attacks; requires taint/dataflow tracking (research direction).

## Reporting

Security reports: open a private security advisory on the GitHub repository. Do not file public issues for exploitable findings.
