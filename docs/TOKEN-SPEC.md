# Token Specification

> Toolgate 0.3 · Last updated 2026-09-03 · Normative for interoperating implementations

Toolgate uses three signed artifacts, all EdDSA (Ed25519) JWS with distinct `typ` headers so they can never be confused for one another.

## 1. Capability token — `tg+jwt`

Minted by the control plane from a delegation grant; consumed by the gate. Standards basis: RFC 8693 (delegation `act`), RFC 9396 (`authorization_details`), RFC 7800 (`cnf`), Transaction Tokens draft (`txn`).

### Header

| Field | Value |
| --- | --- |
| `alg` | `EdDSA` |
| `typ` | `tg+jwt` (verified strictly) |
| `kid` | RFC 7638 thumbprint of the control-plane key |

### Claims

| Claim | Type | Semantics |
| --- | --- | --- |
| `iss` | string | Control plane issuer URL |
| `sub` | string | **The human principal** the work is for (`usr_...`). Never the agent. |
| `act.sub` | string | **The agent actually acting** (`agt_...`). RFC 8693 delegation, not impersonation. |
| `aud` | string | `toolgate:gate` — audience-bound, rejected anywhere else |
| `tenant` | string | Tenant id |
| `grant_id` | string | The durable delegation this token was minted from |
| `scope` | string | Space-delimited coarse scopes. Advisory OAuth-style metadata only — **not** independently enforced by the gate; `authorization_details` is the authoritative bound on what the token can call. |
| `authorization_details` | array | The enforced surface: `[{ "type": "toolgate:tool_call", "upstream": "crm", "tools": ["*"] }]`. Calls outside it are denied before policy runs. |
| `cnf.jkt` | string | RFC 7638 thumbprint of the agent key that must sign call proofs |
| `txn` | string | Per-task transaction id; join key across audit records |
| `iat`, `exp` | int | TTL default 120s, cap 300s, ±15% jitter so harvested batches never expire simultaneously |
| `jti` | string | Unique token id, recorded in every audit record |
| `tg_ver` | `1` | Claim-set version |

### Security properties

- **Stolen token alone: inert.** The gate demands a proof signed by the key in `cnf.jkt`.
- **Stolen token + key: bounded.** Damage ≤ `authorization_details` ∩ policy ∩ remaining budget ∩ remaining TTL.
- **Always attributable.** `sub` (who authorized) ≠ `act.sub` (who acted) in every audit record.
- **Instantly revocable.** The gate checks grant status on every call; revocation outruns TTL.

## 2. Client assertion — `tg-client+jwt`

How an agent authenticates to `POST /v1/token` (RFC 7523 pattern). No shared secrets, no passwords.

| Claim | Requirement |
| --- | --- |
| `iss`, `sub` | Both the agent id; must be equal |
| `aud` | The exact token endpoint URL |
| `iat`, `exp` | TTL ≤ 60s |
| `jti` | **Single-use.** The control plane persists consumed values; replay → `TG_TOKEN_INVALID` |

Signed with the agent's private key; verified against the registered public JWK.

## 3. Proof of possession — `tg-pop+jwt`

One per gate call, following RFC 9449's model (DPoP), hand-implemented because no maintained Python library provides it (authlib #315).

### Header

`alg: EdDSA`, `typ: tg-pop+jwt`, `jwk`: the agent's **public** JWK (bare `kty`/`crv`/`x`; proofs embedding a private key are rejected outright).

### Claims

| Claim | Binding |
| --- | --- |
| `htm` | HTTP method, uppercased |
| `htu` | Exact request URL (`TOOLGATE_PUBLIC_URL` + path) |
| `ath` | base64url(SHA-256(capability token)) — binds proof to one specific token |
| `iat` | Freshness: rejected if older than 60s or more than 5s in the future |
| `jti` | **Single-use**, enforced by the gate's consumed-jti store |

### Verification order (gate)

1. Parse header; require `typ` and embedded public `jwk`; reject if `d` present.
2. Thumbprint(header.jwk) must equal token `cnf.jkt`.
3. Verify JWS signature with the embedded key.
4. Check `htm`, `htu`, `ath`, `iat` window.
5. Consume `jti`; reuse → `TG_PROOF_INVALID`.

## 4. Audit record

Append-only chain; each record:

```json
{
  "seq": 42, "id": "evt_...", "tenantId": "tnt_...", "ts": "2026-09-03T...",
  "actor":   { "agentId": "agt_...", "userId": "usr_...", "grantId": "grt_...", "tokenJti": "..." },
  "action":  { "callId": "call_...", "upstream": "crm", "tool": "read_contact", "argsHash": "sha256hex" },
  "decision":{ "effect": "allow", "source": "rule", "ruleId": "crm-ok", "reason": "..." },
  "result":  { "status": "executed", "httpStatus": 200, "latencyMs": 12.4, "costUnits": 1 },
  "prevHash": "<hash of record 41>",
  "hash": "sha256hex( canonical_json(record minus hash,sig) )",
  "sig": "base64url( Ed25519(gate key, hash) )"
}
```

- `argsHash` = SHA-256 of canonically serialized args: proves *what* was requested without persisting payloads.
- Canonical JSON: recursively sorted keys, compact separators, absent fields dropped.
- Chain verification detects content edits, record removal, reordering, and foreign signatures; genesis `prevHash` is 64 zeros.
- `decision.source` ∈ `token_bounds | rule | constraint | budget | approval | default`.
