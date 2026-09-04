# Operations Runbook

> Toolgate 0.4 · Last updated 2026-09-12 · Audience: operators of a Toolgate deployment

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

Don't watch the queue — push it to where approvers already are:

```bash
toolgate channels add-webhook -t tnt_... --name hooks --url https://ops.example/toolgate
toolgate channels add-slack   -t tnt_... --name slack --channel C0123      # prompts for secrets
toolgate channels add-email   -t tnt_... --name mail --smtp-host smtp.example \
    --from-address toolgate@acme.example --recipient ana@acme.example:op_...
toolgate slack bind -t tnt_... --slack-user U0123 --operator op_...        # attribution
toolgate channels deliveries apr_...                                       # delivery status
```

Slack decisions require a user↔operator binding; email links are single-use and die with the approval. Delivery failures retry with backoff and never affect the approval itself.

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
| Vault KEK (KMS providers) | Rotate the key in the KMS (or point `TOOLGATE_KMS_KEY` at a new key and restart), then `toolgate vault rotate-kek` — re-wraps every data key; **no secret payload is ever decrypted**. Old KEK versions keep unwrapping during the window (KMS decrypt APIs resolve them). Audited. |
| Vault KEK (`env` provider) | Set the new `TOOLGATE_MASTER_KEY`, put the old one in `TOOLGATE_MASTER_KEY_PREVIOUS`, restart, run `toolgate vault rotate-kek`, then drop the previous key. |
| Legacy v1 blobs | `toolgate vault migrate` bulk-converts to v2 envelopes; `toolgate vault status` shows the v1/v2 split. |
| Control-plane / gate signing keys | `toolgate keys rotate control|gate` — kid-overlap keysets; gate rotation writes a signed handoff record so offline verification follows the lineage. Old tokens stay valid through their TTL. |
| Agent keys | Agent-side; register the new public key as a **new agent** and re-grant. |

## R6 — Common integration failures

| Symptom | Cause | Fix |
| --- | --- | --- |
| `TG_PROOF_INVALID: htu mismatch` | `TOOLGATE_PUBLIC_URL` ≠ URL the client calls (proxy, port, trailing slash) | Align the env var with the exact public origin |
| `TG_TOKEN_INVALID: client assertion replayed` | Client retried a token request reusing the assertion | Sign a fresh assertion per attempt (SDK does) |
| `TG_TOKEN_EXPIRED` bursts | Long-running work on one token | Tokens are ~120s by design; call `token()` per operation (SDK caches and refreshes) |
| Upstream 401s recorded as `TG_UPSTREAM_ERROR` | Secret rotated upstream but not re-sealed in Toolgate | Re-POST the upstream credential |


## R7 — Proof-grade anchoring and retention

Checkpoints are cut automatically (every 64 records and on every gate-key rotation); cut one on demand before exports or audits: `curl -X POST $TG/v1/control/audit/checkpoint`.

**Transparency-log anchoring (0.5).** Set `TOOLGATE_REKOR_URL` to a Rekor-compatible log; the background worker publishes every checkpoint (hashedrekord over its canonical signed bytes) and persists the returned `{logId, logIndex, uuid, inclusion proof, signed root}` with the checkpoint. Bundles (`GET /v1/control/audit/bundle`, v2) carry the evidence. Monitor `/healthz` → `anchoring`: `degraded: true` means 3+ consecutive checkpoints failed to anchor — alert on it; anchoring resumes automatically when the log is reachable.

**Proof-grade offline verification.** Obtain the log's public key **out-of-band** (never from the server being audited), then:

```bash
toolgate audit export --out bundle.json
toolgate audit verify --file bundle.json --jwk gate.jwk --rekor --trust-root log.pem
```

This validates hash linkage, signatures, rotation lineage, every checkpoint root, every inclusion proof against the pinned log key, and — decisively — that the presented history still matches what was anchored. A rewritten chain re-signed with a **compromised current gate key** passes signature checks but fails here with a divergence report naming the seq. Exit code `2` on any failure.

**WORM retention.** Schedule immutable exports (cron/systemd timer):

```bash
toolgate audit worm-export --dir /mnt/worm/audit --retention-days 183
toolgate audit worm-export --s3-bucket acme-audit-worm    # Object Lock COMPLIANCE; pip install 'toolgate-io[s3]'
```

Filesystem exports are write-once (`O_EXCL`, mode 0444) with a SHA-256 manifest appended to `manifest.jsonl`; S3 exports use Object Lock COMPLIANCE mode — undeletable until the retention date, even by the bucket owner (the bucket must be created with Object Lock enabled). Default retention is 183 days (≥ 6 months).

The legacy `TOOLGATE_ANCHOR_URL` webhook witness still works and can run alongside Rekor anchoring.

## R8 — Per-user OAuth connections

```bash
toolgate oauth add-app -t tnt_... --name github --client-id ... \
    --authorize-url https://github.com/login/oauth/authorize \
    --token-url https://github.com/login/oauth/access_token --scope repo
# provider redirect URI must be <public-url>/v1/connections/callback (exact match)
toolgate oauth connect -t tnt_... --user usr_... --app oap_...   # prints the authorize URL
toolgate oauth connections -t tnt_...                            # status + token expiry
toolgate oauth revoke con:tnt_...:oap_...:usr_...                # instant; sealed tokens deleted
```

- `TG_CONNECTION_REQUIRED` on a gate call means the grant's user never connected (or was revoked): start a connection, no server change needed.
- Scope growth requires re-consent: update the provider app's scopes, then re-run connect for each user (reconnecting replaces the connection in place).
- Every lifecycle event (start/connect/revoke) lands in the signed audit chain; token material never does.

## R9 — Operator lifecycle

- Create per-person operators (`toolgate operators create --name ... --role auditor|approver|owner`); the `opk_` key is shown once.
- Offboarding: `toolgate operators disable op_...` — immediate.
- The static admin key is break-glass only: its use is audited as `op_breakglass`; alert on that actor id appearing in the chain.
- Every control-plane mutation lands in the signed chain with `decision.source="operator"` — review it like any other audit stream.
