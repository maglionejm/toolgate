# CLI Reference

> Toolgate 0.4 · `pip install toolgate-io` (or `uvx --from toolgate-io toolgate`) · the CLI is a pure client of the control-plane API

```
toolgate [--profile NAME] [--json] COMMAND
```

`--json` switches every command to machine-readable output (the raw API payload) for scripting. Errors print the server's error envelope and exit non-zero (`2` for a failed audit verification, `1` otherwise).

## Configuration

| Command | Purpose |
| --- | --- |
| `toolgate init` | Prompt for URL + admin key, verify `/healthz`, save a profile (`~/.toolgate/config.json`, 0600) |
| env override | `TOOLGATE_URL` + `TOOLGATE_ADMIN_KEY` beat profiles (CI/scripting); `TOOLGATE_CONFIG` relocates the config file |

## Running things

| Command | Purpose |
| --- | --- |
| `toolgate server` | Run the control plane + gate |
| `toolgate demo` | The six-act end-to-end demo |
| `toolgate demo --live` | Same scenario driven by a real Claude model, plus a prompt-injection containment act (`pip install 'toolgate-io[demo]'`, `ANTHROPIC_API_KEY`) |
| `toolgate version` | Version |

## Identity & registry

```bash
toolgate keys generate --out agent-key.json     # private JWK stays local (0600)
toolgate tenants create "Acme"                  # -> tnt_...
toolgate users create -t tnt_... --name "Sam" --email sam@acme.com
toolgate agents register -t tnt_... --name assistant --key agent-key.json   # sends ONLY the public part
toolgate upstreams add -t tnt_... --name crm --base-url https://api.crm.example \
    --mode bearer --secret LIVE-KEY \
    --tool read_contact --tool "delete_contact:1:se"   # name[:cost][:se]
toolgate policies create -t tnt_... --name default --rules-file rules.json
```

Every entity group has `list`; upstream credentials are sealed on write and never appear in any output.

## Delegation

```bash
toolgate grants create -t tnt_... --user usr_... --agent agt_... --policy pol_... \
    --budget 100 --ttl-hours 24 --authz "crm:*" --authz "email:send_email"
toolgate grants list -t tnt_...        # includes live budget bars
toolgate grants show grt_...
toolgate grants revoke grt_... --yes   # live tokens die on their next call
```

## Approvals (human-in-the-loop)

```bash
toolgate approvals list -t tnt_...                    # pending by default
toolgate approvals approve apr_... --by usr_...
toolgate approvals deny apr_... --by usr_...
toolgate approvals watch -t tnt_... --by usr_...      # interactive inbox: prompts per new approval
```

Decisions apply to the exact argument set shown — agents cannot swap arguments afterwards.

## Notification channels (0.5)

```bash
toolgate channels list -t tnt_...
toolgate channels add-webhook -t tnt_... --name hooks --url https://ops.example/toolgate
toolgate channels add-slack   -t tnt_... --name slack --channel C0123   # prompts for secrets
toolgate channels add-email   -t tnt_... --name mail --smtp-host smtp.example \
    --from-address toolgate@acme.example --recipient ana@acme.example:op_...
toolgate channels deliveries apr_...          # per-channel delivery status
toolgate channels delete chn_...
toolgate slack bind -t tnt_... --slack-user U0123 --operator op_...
toolgate slack bindings -t tnt_...
```

Parked approvals fan out to every active channel; decisions from Slack or email carry the bound operator's attribution in the audit chain, exactly like console decisions.

## Audit

```bash
toolgate audit list -t tnt_... --limit 50
toolgate audit verify                                  # server-side chain verification
toolgate audit export --out audit.json                 # full chain + sha256 manifest
toolgate audit verify --file audit.json                # OFFLINE — key fetched from /v1/keys
toolgate audit verify --file audit.json --jwk gate.jwk # fully air-gapped verification
```

Offline verification is the point: an exported chain is checkable by a party that does not trust the server — **but only if you supply the gate's public key out-of-band via `--jwk`**. Without `--jwk`, `audit verify --file` fetches the gate key from `GET /v1/keys` on the very server being audited, so a server that forged the chain could serve a matching key alongside it; that mode confirms internal consistency, not third-party trust. Genuine offline / air-gapped verification requires passing `--jwk` with an independently-obtained key. Exit code `2` when the chain is broken (with `broken_at_seq`).

## Tokens

```bash
toolgate token decode <jwt>            # header + claims, clearly marked NOT verified
toolgate token decode <jwt> --verify   # signature-checked against /v1/keys
```

## Operators (0.4)

```bash
toolgate operators create --name "compliance" --role auditor   # opk_ key shown once
toolgate operators list
toolgate operators disable op_...
```

Profiles accept operator keys; the break-glass admin key still works and is audited as `op_breakglass`.

## Keys & integrity (0.4)

```bash
toolgate keys rotate gate      # signed handoff record, lineage-verifiable offline
toolgate keys rotate control   # old tokens stay valid through their TTL
toolgate audit export --out bundle.json     # records + Merkle checkpoints
toolgate audit verify --file bundle.json    # chain + lineage + checkpoint roots
```

## Simulation & reports (0.4)

```bash
toolgate policies simulate pol_... --upstream email --tool send_email --tainted
toolgate report -t tnt_...     # usage rollup derived from the signed chain
```

## Deploy (0.4)

```bash
toolgate up        # Docker: generates fail-closed secrets (.toolgate.env, 0600), starts the container
```

## Dev harness (act as an agent)

```bash
toolgate dev call crm read_contact --grant grt_... --key agent-key.json --args '{"contactId":"c-01"}'
toolgate dev call email send_email --grant grt_... --key agent-key.json \
    --args '{"to":"cfo@globex.com"}' --wait     # parks, then waits for the human
toolgate dev execute apr_... --grant grt_... --key agent-key.json   # run an approved parked call
```

`dev call` performs the real agent flow — client assertion, token exchange, PoP-signed gate call — so you can exercise policies before wiring the SDK into your agent.
