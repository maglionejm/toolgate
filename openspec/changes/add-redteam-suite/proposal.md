# Red-team test suite for the 0.4 attack surface

## Why
GitHub issue: #9. Regression tests prove yesterday's bugs stay fixed; they do not probe for tomorrow's. The 0.4 surfaces (MCP's PoP-exempt path, rotation lineage, taint policy, checkpoints) have never been attacked on purpose, and the hand-rolled PoP layer is explicitly flagged for adversarial review (docs/SECURITY.md).

## What Changes
- New `tests/redteam/` suite, run as a dedicated CI job, organized as attack modules with an explicit adversary model per module.
- Attack coverage: MCP stolen-token blast radius, forged/absent rotation handoffs, taint evasion (txn splitting, token re-exchange), checkpoint/verifier edge cases, approval arg-swap variants, cross-tenant probes, concurrency races (budget, approval claim).
- A findings policy: every successful attack becomes a failing test + a fix PR or a documented accepted-risk entry in docs/SECURITY.md.

## Impact
- Affected specs: security-testing (new)
- Affected code: tests only (fixes it uncovers land as their own changes)
