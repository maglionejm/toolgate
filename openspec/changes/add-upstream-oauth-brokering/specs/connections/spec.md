# connections Specification

## ADDED Requirements

### Requirement: Tenant OAuth apps
Owners SHALL register per-provider OAuth applications (client id, sealed client secret, endpoints, default scopes) per tenant; secrets SHALL live only in the vault.

#### Scenario: Register app
- **WHEN** an owner registers a provider app
- **THEN** the client secret is sealed and never returned by any read endpoint

### Requirement: User connection via authorization code + PKCE
A user SHALL connect an account through a broker-driven authorization-code flow with PKCE and exact redirect-URI matching; resulting refresh tokens SHALL be sealed server-side and never appear in any agent-facing surface.

#### Scenario: Connect flow
- **WHEN** Sam completes provider consent
- **THEN** the callback stores a sealed connection bound to {tenant, user, provider} and the console shows it as connected

### Requirement: oauth_user credential injection
Upstreams MAY declare credential mode `oauth_user`; the gate SHALL resolve the connection for the calling grant's `userId`, refresh expired access tokens transparently, and inject the live token — the agent and the audit trail SHALL never contain it.

#### Scenario: Expired access token
- **WHEN** a gated call finds the user's access token expired
- **THEN** the broker refreshes it server-side and the call proceeds; refresh failure surfaces as a typed error and is audited

#### Scenario: Missing connection
- **WHEN** the grant's user has no connection for the upstream's provider
- **THEN** the call fails with a typed error naming the connect action, without invoking the upstream

### Requirement: Instant revocation
Revoking a connection SHALL make in-flight and future calls that depend on it fail on next use, independent of provider-side token lifetimes.

#### Scenario: Revoke
- **WHEN** Sam revokes the connection
- **THEN** the next gated call using it is refused and audited; the sealed tokens are deleted
