# token-endpoint-protection Specification

## Purpose
TBD - created by archiving change add-token-endpoint-bruteforce. Update Purpose after archive.

## Requirements

### Requirement: Failure backoff
Consecutive failed token exchanges for the same agent id SHALL trigger exponential backoff (429 + Retry-After), reset by a successful exchange; the backoff state SHALL be independent of successful-traffic rate limits.

#### Scenario: Assertion guessing
- **WHEN** an attacker submits 10 consecutive invalid assertions for one agent id
- **THEN** subsequent attempts receive 429 with growing Retry-After until the window cools

### Requirement: Trusted-proxy source limiting
Per-source limits SHALL key on the direct socket peer unless the peer is in `TOOLGATE_TRUSTED_PROXIES`, in which case the nearest untrusted X-Forwarded-For hop is used; spoofed forwarded headers from untrusted peers SHALL be ignored.

#### Scenario: Spoofed XFF
- **WHEN** an untrusted client sends X-Forwarded-For with rotating addresses
- **THEN** limiting keys on the real socket peer and the rotation buys nothing

### Requirement: Failure visibility
The server SHALL count assertion failures (by reason class) and expose them via healthz detail; a summary SHALL be appended to the audit chain at most hourly when failures occurred.

#### Scenario: Alerting
- **WHEN** failures spike
- **THEN** operators can alert on the healthz counter without parsing logs

### Requirement: Response uniformity
Failed exchanges SHALL keep uniform error shapes and comparable latency across failure causes so probing cannot distinguish unknown grants from bad signatures beyond documented codes.

#### Scenario: Enumeration probe
- **WHEN** an attacker compares responses for unknown-grant vs bad-signature failures
- **THEN** status/code/timing differences do not identify which element failed beyond the existing generic envelope
