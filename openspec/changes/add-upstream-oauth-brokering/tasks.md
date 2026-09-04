## 1. Model & store
- [ ] 1.1 ProviderApp + Connection models (sealed secret refs, scopes, expiry metadata)
- [ ] 1.2 Store tables + accessors; vault sealing of client secrets and token sets

## 2. Broker
- [ ] 2.1 Authorize URL builder (state, PKCE) + callback endpoint; state single-use
- [ ] 2.2 Token exchange + refresh with per-connection locking; failure taxonomy
- [ ] 2.3 Gate injection path for `oauth_user` mode (resolve by grant.userId)

## 3. Lifecycle & surfaces
- [ ] 3.1 Endpoints: apps CRUD (owner), connections list/revoke (user-scoped, auditor read)
- [ ] 3.2 Console: connect button flow + connection management; CLI parity
- [ ] 3.3 Audit every lifecycle event; docs (API, OPERATIONS, SECURITY threat rows: token custody)

## 4. Verification
- [ ] 4.1 Tests with a fake provider (authz-code, refresh, revoke, missing-connection, cross-user isolation)
