# Upstream OAuth brokering (per-user third-party connections)

## Why
GitHub issue: #11. Today an upstream credential is one static tenant-wide secret. Real SaaS tools (Google, Slack, GitHub, CRMs) authorize *users* via OAuth; agents acting for Sam must call with Sam's connection — with Toolgate holding the tokens, never the agent. This is the Arcade/Composio-class capability that unlocks most real integrations.

## What Changes
- Tenant-registered OAuth apps (client id/secret sealed in the vault) per provider.
- Per-user connections established via authorization-code + PKCE; refresh tokens custodied server-side; access tokens injected at execution like static secrets.
- New credential mode `oauth_user`: the gate resolves the connection for the grant's `userId` at call time and refreshes transparently.
- Connection lifecycle: list, revoke (instant), re-consent on scope growth; all audited.

## Impact
- Affected specs: connections (new)
- Affected code: server (new connections router + broker), store, gate injection, console (connect/manage UI), CLI, docs
