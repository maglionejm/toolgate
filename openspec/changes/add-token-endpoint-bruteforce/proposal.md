# Token endpoint brute-force protections

## Why
GitHub issue: #24. The token endpoint verifies agent signatures, so guessing is cryptographically hopeless — but unlimited failures are still free reconnaissance and cheap DoS-by-crypto (every attempt costs a signature verification). #38 added per-grant rate limits; failures and unauthenticated traffic remain unshaped.

## What Changes
- Failure-aware limiting: exponential backoff per (agent id, source) after consecutive failed assertions, independent of the per-grant success limiter.
- Optional per-source limiting keyed by client IP with explicit trusted-proxy configuration (`TOOLGATE_TRUSTED_PROXIES`) — X-Forwarded-For is honored only from trusted hops, else the socket peer is used.
- Failure telemetry: assertion-failure counters exposed on /healthz detail and a periodic audit summary record so operators can alert.
- Constant-response discipline: failure responses SHALL not reveal whether the grant, agent, or signature was the failing element beyond the existing generic codes.

## Impact
- Affected specs: token-endpoint-protection (new)
- Affected code: server/control.py (token route), ratelimit, context config, docs (DEPLOYMENT proxies, SECURITY)
