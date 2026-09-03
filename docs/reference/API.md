# API Reference

> Toolgate 0.2 · Last updated 2026-09-03 · Base URL: your deployment (`TOOLGATE_PUBLIC_URL`)

Three API surfaces with distinct authentication:

| Surface | Prefix | Authentication |
| --- | --- | --- |
| Control plane | `/v1/control/*` | `x-toolgate-admin-key` header |
| Token endpoint | `/v1/token` | Signed client assertion (in body) |
| Gate | `/v1/gate/*` | `Authorization: Bearer <capability token>` + `x-toolgate-proof` |

All request and response bodies are JSON. All errors share one envelope:

```json
{ "error": { "code": "TG_DENIED", "message": "...", "details": { } } }
```

## Error codes

| Code | HTTP | Meaning |
| --- | --- | --- |
| `TG_TOKEN_INVALID` | 401 | Token/assertion malformed, wrong signature, wrong audience, or replayed |
| `TG_TOKEN_EXPIRED` | 401 | Capability token or grant past expiry |
| `TG_PROOF_INVALID` | 401 | PoP proof missing, wrong key, wrong URL/method, stale, or replayed |
| `TG_DENIED` | 403 | Policy or token bounds denied the call |
| `TG_APPROVAL_DENIED` | 403 | Approval was denied, expired, or already executed |
| `TG_APPROVAL_PENDING` | 409 | Execution attempted before the human decided |
| `TG_BUDGET_EXCEEDED` | 403 | Grant budget cannot cover the call cost |
| `TG_REVOKED` | 403 | Grant revoked or agent disabled |
| `TG_NOT_FOUND` | 404 | Unknown entity |
| `TG_VALIDATION` | 400 | Malformed request body or parameters |
| `TG_UPSTREAM_ERROR` | 502 | Upstream unreachable or returned an error status |
| `TG_INTERNAL` | 500 | Unexpected server error |

---

## Control plane

### POST /v1/control/tenants

Create a tenant. → `201`

```json
// request
{ "name": "Acme Corp" }
// response
{ "id": "tnt_...", "name": "Acme Corp", "createdAt": "2026-09-03T..." }
```

### POST /v1/control/users

Create a human principal. → `201`

| Field | Type | Required | Notes |
| --- | --- | --- | --- |
| `tenantId` | string | yes | |
| `displayName` | string | yes | |
| `email` | string | no | |

### POST /v1/control/agents

Register an agent identity. → `201`

| Field | Type | Required | Notes |
| --- | --- | --- | --- |
| `tenantId` | string | yes | |
| `name` | string | yes | |
| `publicJwk` | object | yes | Ed25519 public JWK (`kty: OKP`, `crv: Ed25519`, `x`). Never send the private key. |

Response includes `status: "active"`. Agents can be disabled to revoke all their access at the identity grain.

### POST /v1/control/upstreams

Register a tool backend and seal its credential into the vault. → `201`

| Field | Type | Required | Notes |
| --- | --- | --- | --- |
| `tenantId` | string | yes | |
| `name` | string | yes | Stable name referenced by policies and tokens (e.g. `crm`) |
| `baseUrl` | string | yes | Tool calls POST to `{baseUrl}/tools/{tool}` |
| `credential.mode` | `bearer` \| `header` \| `query` | yes | How the gate injects the secret |
| `credential.secret` | string | yes | **Write-only.** Sealed with AES-256-GCM; response carries `secretRef`, never the value |
| `credential.headerName` | string | `header` mode | |
| `credential.paramName` | string | `query` mode | |
| `tools[]` | array | yes | `{ name, description?, sideEffecting?, costUnits? }` — `costUnits` defaults to 1 |

### POST /v1/control/policies

Create an ordered rule set. First matching rule wins; **no match means deny**. → `201`

```json
{
  "tenantId": "tnt_...",
  "name": "assistant-policy",
  "rules": [
    { "id": "no-deletes", "effect": "deny",
      "match": { "upstream": "crm", "tool": "delete_*" } },
    { "id": "external-email", "effect": "require_approval",
      "match": { "upstream": "email", "tool": "send_email",
                 "where": [ { "path": "to", "op": "matches", "value": "@(?!acme\\.com)" } ] } },
    { "id": "crm-ok", "effect": "allow",
      "match": { "upstream": "crm", "tool": "*" },
      "constraints": { "maxCostUnits": 5 } }
  ]
}
```

- `match.upstream` / `match.tool`: glob patterns (`*` matches any run of characters); absent = any.
- `match.where[]`: argument constraints that must **all** hold. `path` is a dot path into call args. Ops: `eq, neq, gt, gte, lt, lte, in, contains, startsWith, matches` (regex).
- `constraints.maxCostUnits`: calls costing more are denied even when the rule allows.

### POST /v1/control/grants

Record a delegation from a user to an agent. → `201`

| Field | Type | Required | Notes |
| --- | --- | --- | --- |
| `tenantId`, `userId`, `agentId`, `policyId` | string | yes | All must exist |
| `scopes` | string[] | no | Coarse labels copied into the token `scope` claim |
| `authorization[]` | array | yes | `{ upstream, tools[] }` — `"*"` allowed; becomes token `authorization_details` |
| `budgetMaxUnits` | int > 0 | yes | Total cost units this delegation may spend |
| `ttlHours` | number | no | Default 24 |

### POST /v1/control/grants/{id}/revoke

Immediate kill switch: live capability tokens minted from this grant stop working on their next call. → `200 { "id", "status": "revoked" }`

### GET /v1/control/approvals?tenantId=...&status=pending

List approval requests. Statuses: `pending`, `approved`, `denied`, `expired`, `executed`.

### POST /v1/control/approvals/{id}/decide

```json
{ "decision": "approve" | "deny", "decidedBy": "usr_..." }
```

Only `pending`, unexpired approvals can be decided. The decision applies to the **exact argument set** captured when the call was parked.

### GET /v1/control/audit?tenantId=...

Ordered audit records (see [TOKEN-SPEC](../TOKEN-SPEC.md) for the record schema). Denials and budget refusals are recorded, not only executions.

### GET /v1/control/audit/verify

Re-verifies the entire hash chain and every signature.

```json
{ "valid": true, "length": 128 }
// or
{ "valid": false, "length": 128, "broken_at_seq": 57, "reason": "record content does not match its hash" }
```

---

## Token endpoint

### POST /v1/token

RFC 8693-style exchange. Not admin-authed — the client assertion is the authentication.

```json
// request
{
  "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
  "client_assertion": "<EdDSA JWS, typ tg-client+jwt, aud = this URL>",
  "grant_id": "grt_...",
  "requested_ttl_seconds": 120
}
// response 200
{
  "access_token": "<capability token>",
  "token_type": "Bearer",
  "issued_token_type": "urn:ietf:params:oauth:token-type:access_token",
  "expires_in": 118,
  "jti": "...",
  "txn": "txn_..."
}
```

Rejections: unknown grant (404), revoked grant/agent (403 `TG_REVOKED`), expired grant (401), assertion signature/audience mismatch or **assertion jti reuse** (401 `TG_TOKEN_INVALID`). TTL is capped at 300 seconds regardless of the request.

---

## Gate

All side-effecting gate endpoints require **two** credentials: the capability token *and* a one-time proof-of-possession JWS in `x-toolgate-proof`, signed by the agent key bound in the token's `cnf.jkt`, over the method, exact URL, and token hash. The SDK does this automatically.

### POST /v1/gate/call/{upstream}

```json
// request
{ "tool": "read_contact", "args": { "contactId": "c-001" } }

// 200 — executed
{ "status": "executed", "call_id": "call_...", "result": { } }

// 202 — parked for human approval
{ "status": "pending_approval", "approval_id": "apr_...", "expires_at": "...", "reason": "..." }

// 4xx — denied (see error codes)
```

Pipeline, in order: token verify → grant/agent liveness → proof verify (single-use) → tool resolution → token bounds → policy decision → atomic budget charge → vault credential injection → upstream call → audit append. Every terminal outcome is audited.

### GET /v1/gate/approvals/{id}

Poll an approval's status. Requires the capability token of the same grant (no proof needed for reads).

### POST /v1/gate/approvals/{id}/execute

Execute an approved call. The **stored** (approved) arguments are used — arguments cannot be re-submitted. One execution per approval; subsequent attempts return `TG_APPROVAL_DENIED`.

---

## Health

`GET /healthz` → `{ "ok": true, "issuer": "...", "control_kid": "..." }` (no auth).
