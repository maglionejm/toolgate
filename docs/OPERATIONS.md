# Operations Runbook

> Toolgate 0.3 · Last updated 2026-09-03 · Audience: operators of a Toolgate deployment

## R1 — Emergency: revoke an agent's access

Symptoms: compromised agent host, leaked agent key, or misbehaving automation.

1. **Revoke the grant** (kills live tokens on their next call — do not wait for TTL):
   ```bash
   curl -X POST $TG/v1/control/grants/grt_.../revoke -H "$TG_ADMIN"
   ```
2. If the *agent identity* is compromised (key theft), disabling the identity blocks every grant it holds — currently via direct store update (`status: "disabled"`); an API endpoint is tracked in the backlog.
3. Confirm: the next gate call must return `TG_REVOKED`; check the audit trail for calls between suspected compromise and revocation:
   ```bash
   curl -s "$TG/v1/control/audit?tenantId=tnt_..." -H "$TG_ADMIN" | jq '.[] | select(.actor.agentId=="agt_...")'
   ```
4. Re-issue: register a **new agent keypair** (never reuse the old one), create a fresh grant with the minimum needed authorization.

## R2 — Working the approvals queue

```bash
curl -s "$TG/v1/control/approvals?tenantId=tnt_...&status=pending" -H "$TG_ADMIN"
```

Decision discipline:

- Read `args` — the decision applies to **exactly** those values; the agent cannot change them afterwards.
- `decidedBy` must identify a real operator/user — it lands in the audit record verbatim.
- Approvals expire (default 10 minutes); expired items need the agent to re-request, which is intentional.
- Systematic pattern (same tool, same shape, always approved) → move it to an `allow` rule with a `where` constraint instead of rubber-stamping; approval fatigue is an attack surface (OWASP T10).

## R3 — Audit verification and export

Continuous: alert on `GET /v1/control/audit/verify` returning `valid: false`.

A broken chain means the store was modified outside the gate — treat as an incident:
`broken_at_seq` marks the first bad record; everything before it is still proven intact. Preserve the DB file immediately (copy, hash it) before any further writes.

Export for retention/compliance (≥ 6 months, EU AI Act Art 26(6)):

```bash
curl -s "$TG/v1/control/audit" -H "$TG_ADMIN" > audit-$(date +%F).json
sha256sum audit-$(date +%F).json >> audit-manifest.txt
```

Store exports on WORM/object-lock storage. External Merkle anchoring is tracked (#12).

## R4 — Budget management

- Remaining budget: `spentUnits` vs `maxUnits` on the grant (control-plane read of the grant, or last audit record's cost accumulation).
- Budgets are **not refillable by design** — issue a new grant. That keeps every spend attributable to one explicit delegation.
- Agents hitting `TG_BUDGET_EXCEEDED` repeatedly usually means costUnits are mispriced on tools, or the delegation is scoped too small for the task; both are policy decisions, not incidents.

## R5 — Key and secret hygiene

| Item | Rotation |
| --- | --- |
| Admin key | Set new `TOOLGATE_ADMIN_KEY`, restart. Old key dies at boot. |
| Upstream secret | Re-POST the upstream with the new secret (re-seals; same name keeps policies valid). |
| Vault master key | **Requires re-sealing every secret** — planned as part of KMS envelope work (#8). Until then treat as fixed. |
| Control-plane / gate signing keys | Not yet rotatable in place (tokens/audit verify against the stored key). Rotation with `kid` overlap is a pre-GA requirement. |
| Agent keys | Agent-side; register the new public key as a **new agent** and re-grant. |

## R6 — Common integration failures

| Symptom | Cause | Fix |
| --- | --- | --- |
| `TG_PROOF_INVALID: htu mismatch` | `TOOLGATE_PUBLIC_URL` ≠ URL the client calls (proxy, port, trailing slash) | Align the env var with the exact public origin |
| `TG_TOKEN_INVALID: client assertion replayed` | Client retried a token request reusing the assertion | Sign a fresh assertion per attempt (SDK does) |
| `TG_TOKEN_EXPIRED` bursts | Long-running work on one token | Tokens are ~120s by design; call `token()` per operation (SDK caches and refreshes) |
| Upstream 401s recorded as `TG_UPSTREAM_ERROR` | Secret rotated upstream but not re-sealed in Toolgate | Re-POST the upstream credential |
