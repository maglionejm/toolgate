# Quickstart

> Toolgate 0.5 · Last updated 2026-09-04 · Audience: application engineers integrating an agent

This guide takes you from zero to a policy-gated, human-approvable, fully audited agent tool call in about ten minutes. Everything runs locally.

> **Prefer the CLI.** Every curl below has a one-line `toolgate` equivalent — see the [CLI reference](reference/CLI.md). The short version:
>
> ```bash
> pip install toolgate-io
> # In production the server fails closed without these keys; set them explicitly.
> TOOLGATE_MASTER_KEY=$(openssl rand -hex 32) TOOLGATE_ADMIN_KEY=$(openssl rand -hex 24) toolgate server &   # server logs only the key fingerprint, not the key
> toolgate init                # save profile
> toolgate keys generate --out agent-key.json
> toolgate tenants create "Acme"
> toolgate users create -t tnt_... --name "Sam"
> toolgate agents register -t tnt_... --name assistant --key agent-key.json
> toolgate upstreams add -t tnt_... --name crm --base-url https://api.your-crm.example \
>     --mode bearer --tool read_contact --tool "update_contact:2:se"
> toolgate policies create -t tnt_... --name default --rules-file rules.json
> toolgate grants create -t tnt_... --user usr_... --agent agt_... --policy pol_... \
>     --budget 100 --authz "crm:*"
> toolgate dev call crm read_contact --grant grt_... --key agent-key.json --args '{"contactId":"c-001"}'
> ```
>
> The raw API path below remains fully supported.

> **0.4:** create per-person operators (`toolgate operators create`) instead of sharing the admin key, open the console at `http://localhost:8484/console`, and try the MCP surface — any MCP client can consume your gated tools at `POST /v1/mcp` with a capability token.

> **0.5:** push parked approvals to Slack/webhooks/email (`toolgate channels`), connect users' own SaaS accounts (`toolgate oauth`, credential mode `oauth_user`), anchor the audit chain in a transparency log (`TOOLGATE_REKOR_URL`), move secret custody to a KMS (`TOOLGATE_VAULT_PROVIDER`), and scale horizontally on Postgres (`TOOLGATE_DB=postgres://…`).

> **Live demo.** `toolgate demo` runs the scripted six-act scenario offline. With `pip install 'toolgate-io[demo]'` and `ANTHROPIC_API_KEY` set, `toolgate demo --live` lets a real Claude model choose every tool call — and adds a prompt-injection act where a hostile page orders exfiltration through an allowed email tool and the taint policy parks it, whatever the model decides.

## 1. Install and boot

```bash
uv sync
# Set the keys explicitly — the server fails closed without them and logs only a
# fingerprint of the admin key, never the key itself. (Use TOOLGATE_DEV=1 to allow
# ephemeral dev keys instead.)
TOOLGATE_MASTER_KEY=$(openssl rand -hex 32) TOOLGATE_ADMIN_KEY=$(openssl rand -hex 24) uv run toolgate-server
# [toolgate] control plane + gate listening on :8484
# [toolgate] admin key fingerprint: <sha256 prefix>   <- confirms which key is active; the key value is not logged
```

Use the `TOOLGATE_ADMIN_KEY` value you set above wherever the admin header is required below.

Export for convenience:

```bash
export TG=http://localhost:8484
export TG_ADMIN="x-toolgate-admin-key: tgk_..."
```

## 2. Register your tenant, user, and agent

The agent generates a keypair; **only the public half is ever sent to Toolgate**.

```python
from toolgate.sdk import generate_ed25519_key_pair
keys = generate_ed25519_key_pair()
print(keys.public_jwk)   # register this
# keys.private_jwk stays with the agent — the only secret it will ever hold
```

```bash
curl -s $TG/v1/control/tenants  -H "$TG_ADMIN" -d '{"name":"Acme"}'
curl -s $TG/v1/control/users    -H "$TG_ADMIN" -d '{"tenantId":"tnt_...","displayName":"Sam"}'
curl -s $TG/v1/control/agents   -H "$TG_ADMIN" \
  -d '{"tenantId":"tnt_...","name":"assistant","publicJwk":{...}}'
```

## 3. Register an upstream with its real credential

The secret is sealed into the vault on write and never appears in any response, token, or log again.

```bash
curl -s $TG/v1/control/upstreams -H "$TG_ADMIN" -d '{
  "tenantId": "tnt_...",
  "name": "crm",
  "baseUrl": "https://api.your-crm.example",
  "credential": {"mode": "bearer", "secret": "LIVE-CRM-KEY"},
  "tools": [
    {"name": "read_contact", "costUnits": 1},
    {"name": "update_contact", "sideEffecting": true, "costUnits": 2}
  ]
}'
```

## 4. Write a policy

Ordered rules, first match wins, no match = deny.

```bash
curl -s $TG/v1/control/policies -H "$TG_ADMIN" -d '{
  "tenantId": "tnt_...",
  "name": "assistant-policy",
  "rules": [
    {"effect": "require_approval", "match": {"tool": "update_contact"}},
    {"effect": "allow", "match": {"upstream": "crm"}}
  ]
}'
```

## 5. Delegate

Sam grants the agent bounded authority: these tools, this budget, this policy, for 24 hours.

```bash
curl -s $TG/v1/control/grants -H "$TG_ADMIN" -d '{
  "tenantId": "tnt_...", "userId": "usr_...", "agentId": "agt_...",
  "policyId": "pol_...",
  "authorization": [{"upstream": "crm", "tools": ["*"]}],
  "budgetMaxUnits": 100
}'
```

## 6. Call a tool from the agent

```python
from toolgate.sdk import ToolgateClient, PendingApproval

client = ToolgateClient(
    base_url="http://localhost:8484",
    agent_id="agt_...",
    agent_private_jwk=keys.private_jwk,
    grant_id="grt_...",
)

result = client.call("crm", "read_contact", {"contactId": "c-001"})
print(result.result)          # executed: policy allowed it

parked = client.call("crm", "update_contact", {"contactId": "c-001", "phone": "+34..."})
assert isinstance(parked, PendingApproval)   # side-effecting -> human required
```

Approve it (your app's approval UI calls this; here, curl):

```bash
curl -s $TG/v1/control/approvals/apr_.../decide -H "$TG_ADMIN" \
  -d '{"decision": "approve", "decidedBy": "usr_..."}'
```

```python
executed = client.wait_for_approval(parked.approval_id)
print(executed.result)        # ran with exactly the approved arguments
```

## 7. Verify the audit trail

```bash
curl -s $TG/v1/control/audit/verify -H "$TG_ADMIN"
# {"valid": true, "length": 4}
```

## Where to go next

- [API reference](reference/API.md) — every endpoint, field, and error code
- [Token specification](TOKEN-SPEC.md) — what's inside a capability token and a call proof
- [Security model](SECURITY.md) — threat matrix and guarantees
- [Deployment](DEPLOYMENT.md) — production configuration and Cloud Run
- [Operations](OPERATIONS.md) — revocation, approvals, audit runbooks
