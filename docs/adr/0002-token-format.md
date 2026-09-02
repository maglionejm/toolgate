# ADR 0002: JWT on OAuth rails, not Biscuits/Macaroons/UCAN

**Status**: accepted · 2026-09-02

## Context

Capability-token formats with offline attenuation (Biscuit v3, Macaroons, UCAN, ZCAP-LD) are technically elegant. Adoption reality (Sept 2026): Biscuit is niche (Clever Cloud), UCAN has one production user, ZCAP-LD is dormant, GNAP standardized but near-zero production. Meanwhile the IETF absorbed capability semantics into OAuth machinery: RFC 9396 `authorization_details`, Transaction Tokens, RFC 8693 `act` chains. Bluesky notably chose OAuth scopes over UCAN despite employing UCAN's co-author.

## Decision

EdDSA (Ed25519) JWTs via `jose`, with capability semantics expressed in standard claims: `authorization_details` (RFC 9396), `act` (RFC 8693), `cnf.jkt` (RFC 7800, DPoP-style proofs per RFC 9449's model), `txn` (Transaction Tokens alignment). Custom typ `tg+jwt` to prevent confusion with other JWT uses.

Ed25519 over ES256: deterministic signatures, no nonce-reuse foot-gun, fast verification, and it matches the WEBBOTAUTH direction (Ed25519 HTTP message signatures).

## Consequences

- Interop with the entire OAuth/MCP toolchain; auditable with standard JWT tooling.
- No offline attenuation (an agent cannot narrow its own token without the control plane) — acceptable: attenuation happens at mint time from the grant, and we prefer the control plane in the loop for metering anyway.
