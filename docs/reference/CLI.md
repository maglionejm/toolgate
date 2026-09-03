# CLI Reference

> Toolgate 0.3 · `pip install toolgate-io` (or `uvx --from toolgate-io toolgate`) · the CLI is a pure client of the control-plane API

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

## Audit

```bash
toolgate audit list -t tnt_... --limit 50
toolgate audit verify                                  # server-side chain verification
toolgate audit export --out audit.json                 # full chain + sha256 manifest
toolgate audit verify --file audit.json                # OFFLINE — key fetched from /v1/keys
toolgate audit verify --file audit.json --jwk gate.jwk # fully air-gapped verification
```

Offline verification is the point: an exported chain is checkable by a party that does not trust the server. Exit code `2` when the chain is broken (with `broken_at_seq`).

## Tokens

```bash
toolgate token decode <jwt>            # header + claims, clearly marked NOT verified
toolgate token decode <jwt> --verify   # signature-checked against /v1/keys
```

## Dev harness (act as an agent)

```bash
toolgate dev call crm read_contact --grant grt_... --key agent-key.json --args '{"contactId":"c-01"}'
toolgate dev call email send_email --grant grt_... --key agent-key.json \
    --args '{"to":"cfo@globex.com"}' --wait     # parks, then waits for the human
toolgate dev execute apr_... --grant grt_... --key agent-key.json   # run an approved parked call
```

`dev call` performs the real agent flow — client assertion, token exchange, PoP-signed gate call — so you can exercise policies before wiring the SDK into your agent.
