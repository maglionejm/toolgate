# Security Policy

Toolgate is security infrastructure: reports are taken seriously and handled with priority.

## Reporting a vulnerability

- **Please do not open a public issue for exploitable findings.**
- Use GitHub's [private vulnerability reporting](../../security/advisories/new) on this repository.
- Include: affected component, reproduction steps, and impact assessment. Proof-of-concept code is welcome.
- You will receive an acknowledgement within 72 hours.

## Scope of interest

Highest-value targets, in order:

1. The proof-of-possession layer (`toolgate/core/assertion.py`) — hand-implemented (no maintained Python DPoP library exists); theft, replay, downgrade, and confusion attacks especially welcome.
2. Token verification and claim enforcement (`toolgate/core/token.py`, gate pipeline).
3. Audit-chain integrity (`toolgate/core/audit.py`) — any way to alter history that verification does not detect.
4. Policy-engine bypasses (glob/constraint edge cases, tool resolution).
5. Vault handling and credential-leak paths.

## Current status

Pre-1.0. The threat model, guarantees, and **known gaps** are documented honestly in [docs/SECURITY.md](docs/SECURITY.md) — please read it before reporting items already listed there (admin-plane hardening, external audit anchoring, and KMS envelope encryption are known and tracked).
