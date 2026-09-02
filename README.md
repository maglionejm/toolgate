# Toolgate

**The capability control plane for embedded AI agents.**

Agents should never hold credentials. Toolgate sits between agents and the tools they call: agents present short-lived, scoped capability tokens; Toolgate validates policy, injects real credentials server-side, executes the call, meters usage, and writes a signed, hash-chained audit trail.

> Status: early MVP under active development.

## Packages

| Package | Purpose |
| --- | --- |
| `@toolgate/core` | Domain core: capability tokens, delegation grants, policy engine, audit chain |
| `@toolgate/server` | Control plane API (identity, grants, token exchange, approvals) + the gate (tool proxy) |
| `@toolgate/sdk` | TypeScript SDK for agents and host applications |
| `@toolgate/demo` | End-to-end demo: agent + mock upstream tools through the gate |

## Development

```bash
pnpm install
pnpm typecheck
pnpm test
pnpm demo
```

See `docs/ARCHITECTURE.md` for the design and `docs/adr/` for decision records.
