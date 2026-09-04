# Security Model

> Toolgate 0.4 · Last updated 2026-09-12

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
| T13 | Body substitution under a captured proof | Proof v2 `cd` claim binds the exact request bytes | Gate | yes |
| T14 | Gate-key compromise -> silent history re-signing | Merkle checkpoints + anchoring; rotation lineage in-chain | Audit | yes |
| T15 | Tool-chain exfiltration (lethal trifecta) | txn taint + `when.txnTouchedUntrusted` policies | Gate + policy | yes |
| T16 | Anonymous or over-broad admin actions | Operator identities + roles; break-glass audited | Control plane | yes |
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

## Approval push channels (#13)

Decisions can arrive from outside the console; each channel authenticates differently and all of them land in the same signed audit chain with operator attribution.

- **Webhook (outbound)** — payloads are signed with the current gate key as a detached JWS over the exact body bytes (`x-toolgate-signature`, kid in `x-toolgate-kid`). Receivers MUST verify against `GET /v1/keys` `gate_jwks` and dedupe on `x-toolgate-delivery`; an unverified webhook body is attacker-controllable input. Webhooks carry the approval args — treat receiver endpoints as sensitive.
- **Slack (inbound)** — interactivity callbacks are verified with Slack's v0 HMAC scheme (channel signing secret, 5-minute replay window) and then mapped through an explicit Slack-user → operator binding. No binding, no decision: Slack display names are not identity. Bot token and signing secret are sealed in the vault at channel creation and never returned by the API.
- **Email magic links (inbound)** — links are single-use tokens (only the SHA-256 is stored), bound to `{approval id, args hash, decision, operator}`, and expire no later than the approval itself. A replayed, expired, or args-mismatched link decides nothing. Threats accepted and mitigated: mail forwarding delegates the decision to whoever holds the inbox (bind recipients to real operators, keep approval TTLs short); mailbox scanners that prefetch URLs will consume a link — the response page states clearly whether a decision happened.

## Known gaps (tracked, not hidden)

- **Operator auth**: per-operator keys, not passkeys/OIDC; no MFA yet (ADR 0006 follow-up).
- **MCP surface** trades PoP sender-binding for ecosystem compatibility (ADR 0009); set `mcp_enabled=False` to refuse it.
- **Tenant isolation** relies on application-level filters over a shared SQLite file; no per-tenant encryption.
- **Vault** master key is env-based; KMS envelope encryption pending (#8).
- **Anchoring** ships as a webhook witness; Rekor inclusion/consistency proofs pending (#12).
- **Taint** is binary and per-txn; field-level dataflow is future work (ADR 0008).

## Red-team findings register

The adversarial suite (`tests/redteam/`, CI job `redteam`) asserts every guarantee below; a successful attack fails the build.

| Finding | Status |
| --- | --- |
| Taint laundering via txn-splitting (fresh token = clean txn) | **Accepted risk under default `taint_scope=txn`**; closed by `TOOLGATE_TAINT_SCOPE=grant` (one untrusted read then taints the whole delegation). Choose per deployment. |
| History rewrite by an adversary holding the *current* gate key | Future records are theirs by definition; rewrites of anchored history are detected by checkpoint verification. Anchor externally (`TOOLGATE_ANCHOR_URL`). |
| Forged rotation handoffs / unintroduced kids | Rejected by lineage verification (chain breaks at the forged record). |
| Stolen MCP bearer token | Bounded: authorization_details ∩ policy ∩ budget ∩ TTL; PoP surfaces unusable; revocation immediate. |

## Reporting

Security reports: open a private security advisory on the GitHub repository. Do not file public issues for exploitable findings.
