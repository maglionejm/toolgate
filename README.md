# Toolgate

**The capability control plane for embedded AI agents.**

[![CI](https://github.com/maglionejm/toolgate/actions/workflows/ci.yml/badge.svg)](https://github.com/maglionejm/toolgate/actions/workflows/ci.yml)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-c8f169)](LICENSE)
[![Python 3.12+](https://img.shields.io/badge/python-3.12%2B-8b96a1)](pyproject.toml)

**Portal & live simulation: [maglionejm.github.io/toolgate](https://maglionejm.github.io/toolgate/)** — try the gate and tamper with a real hash chain in your browser.

Agents should never hold credentials — not the user's OAuth token, not a tenant API key, not anything. Toolgate sits between agents and the tools they call:

- the agent authenticates with **its own Ed25519 key** and a **delegation grant** from a human;
- it receives **short-lived capability tokens** (`sub` = the human, `act.sub` = the agent, RFC 8693 semantics) that are useless if stolen (proof-of-possession bound);
- every tool call is **policy-checked** (allow / deny / require human approval), **metered** against the grant's budget, and executed by the gate, which **injects the real credential server-side**;
- every decision — including denials — lands in a **hash-chained, Ed25519-signed audit trail**.

```
Agent (no secrets) ── token + one-time proof ──▶ GATE ── real credential ──▶ Upstream API
                                                  │
                                    verify → decide → budget → inject → execute → audit
```

## Try it

```bash
uvx --from toolgate-io toolgate demo    # zero-install, straight from PyPI
```

or from source:

```bash
uv sync
uv run toolgate demo
```

The demo boots Toolgate plus two credential-guarded mock APIs and runs a six-act scenario: an allowed CRM read (the upstream rejects anything without its live key — proving injection), a policy denial, an external email parked for human approval and executed against the approved args only, budget exhaustion, revocation that kills a live token instantly, and audit chain verification with the full decision trace.

```
[OK      ] read_contact executed -> {'contact': {...}}
[DENIED  ] TG_DENIED: matched deny rule never-delete
[PARKED  ] approval apr_... pending — agent is blocked, not trusted
[HUMAN   ] Sam approved the exact parked arguments (args are hash-bound)
[OK      ] send_email executed after approval
[BUDGET  ] blocked: delegation grant budget exhausted
[REVOKED ] TG_REVOKED: live token died with the grant, no TTL wait
[AUDIT   ] chain of 10 records — verification: VALID
```

## How it works

1. **Register** a tenant, its users, agents (public keys only), and upstreams. Upstream credentials are sealed into the vault (AES-256-GCM) and never leave the server.
2. **Delegate**: a user grants an agent bounded authority — which upstreams/tools (RFC 9396-style `authorization_details`), what budget (cost units), which policy, until when.
3. **Exchange**: the agent presents a signed client assertion (RFC 7523 style) and receives a capability token — TTL ~2 minutes with jitter, audience-bound, sender-constrained via `cnf.jkt`.
4. **Call**: each gate call carries the token plus a one-time DPoP-style proof signed by the agent key (bound to method, URL, and token hash; replays rejected).
5. **Enforce**: token bounds → policy rules (first match wins, glob matching, dot-path argument constraints, cost ceilings) → default deny → atomic budget charge.
6. **Approve**: `require_approval` parks the call; a human decides on the exact argument set (hash-bound — no post-approval swaps); the agent polls and executes.
7. **Audit**: every decision appends to a hash chain signed by the gate key. `GET /v1/control/audit/verify` proves nothing was edited, removed, or reordered.

## CLI

Everything an operator does is a `toolgate` command ([full reference](docs/reference/CLI.md)):

```bash
pip install toolgate-io
toolgate init                                        # profile + connectivity check
toolgate keys generate --out agent-key.json          # agent identity (private key stays local)
toolgate grants create -t tnt_... --user usr_... --agent agt_... \
    --policy pol_... --budget 100 --authz "crm:*"    # bounded delegation
toolgate approvals watch -t tnt_... --by usr_...     # interactive human-in-the-loop inbox
toolgate audit export --out audit.json && toolgate audit verify --file audit.json   # verify an exported chain
toolgate dev call crm read_contact --grant grt_... --key agent-key.json             # act as the agent
```

> **Offline-verification caveat.** `audit verify --file` is genuinely offline/third-party only when you supply the gate's public key out-of-band via `--jwk`. Without `--jwk`, the verifier fetches the key from `GET /v1/keys` on the very server being audited — so a server that forged the chain could also serve a matching key. For independent verification, pass `--jwk` with a key you obtained separately.

## Agent-side SDK

```python
from toolgate.sdk import ToolgateClient, PendingApproval, generate_ed25519_key_pair

client = ToolgateClient(
    base_url=base_url,
    agent_id=agent_id,
    agent_private_jwk=agent_private_jwk,  # the only secret an agent ever holds
    grant_id=grant_id,
)

result = client.call("crm", "read_contact", {"contactId": "c-001"})
if isinstance(result, PendingApproval):
    result = client.wait_for_approval(result.approval_id)
# Denials, budget exhaustion, and revocation raise typed ToolgateCallError
# (TG_DENIED / TG_BUDGET_EXCEEDED / TG_REVOKED / TG_PROOF_INVALID / ...).
```

## Layout

| Module | Purpose |
| --- | --- |
| `toolgate.core` | Capability tokens, client assertions + PoP proofs, policy engine, audit chain |
| `toolgate.server` | Control plane (registry, grants, token endpoint, approvals, revocation, audit) + gate (enforcement pipeline, vault) |
| `toolgate.sdk` | Agent-side client: token exchange, signed calls, approval flow, typed errors |
| `toolgate.demo` | End-to-end scenario (`uv run toolgate-demo`) |

## Documentation

Full suite in [`docs/`](docs/README.md): [Quickstart](docs/QUICKSTART.md) · [API Reference](docs/reference/API.md) · [Token Spec](docs/TOKEN-SPEC.md) · [Security Model](docs/SECURITY.md) · [Deployment](docs/DEPLOYMENT.md) · [Operations](docs/OPERATIONS.md)

## Design

- `docs/ARCHITECTURE.md` — components, token design, threat model
- `docs/adr/0001` — delegation, never user-credential impersonation
- `docs/adr/0002` — JWT on OAuth rails (RFC 8693/9396/7800) over Biscuit/Macaroon/UCAN
- `docs/adr/0003` — original TS runtime decision (superseded by 0005)
- `docs/adr/0004` — approvals bound to args hashes; hash-chained signed audit
- `docs/adr/0005` — Python as the reference implementation

Roadmap lives in the [issue tracker](../../issues): MCP compatibility, upstream OAuth brokering, Merkle checkpoint anchoring, approvals via Slack/webhooks/CIBA push, dashboard, Postgres scale-out, TypeScript SDK rebuild.

## Development

```bash
uv sync
uv run ruff check src tests
uv run pytest tests/ -q     # 39 tests: core unit + server integration + SDK-vs-server
uv run toolgate-demo        # the six-act scenario
uv run toolgate-server      # standalone server (logs only the admin-key fingerprint at boot; set TOOLGATE_ADMIN_KEY explicitly)
```

Production env vars: `TOOLGATE_MASTER_KEY`, `TOOLGATE_ADMIN_KEY`, `TOOLGATE_PUBLIC_URL`, `TOOLGATE_DB`, `PORT`.

## Contributing & security

Contributions welcome — see [CONTRIBUTING.md](CONTRIBUTING.md). Security findings go through [private vulnerability reporting](SECURITY.md), never public issues.

## License

[Apache License 2.0](LICENSE) © 2026 Juan Martin Maglione. Toolgate is early-stage software (pre-1.0): the wire format is a compatibility surface we take seriously, but expect movement before 1.0.
