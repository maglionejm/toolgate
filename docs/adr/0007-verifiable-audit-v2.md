# ADR 0007: Verifiable audit v2 — key rotation lineage and Merkle checkpoints

**Status**: accepted · 2026-09-12

## Context

The v0.3 chain was tamper-evident only while the gate key stayed honest and static: keys could not rotate, and a stolen gate key could re-sign rewritten history.

## Decision

1. **Rotation with in-chain lineage.** Keys live in keysets (newest signs; all verify by `kid`). Gate rotation appends a handoff record signed by the *old* key naming the new kid (`meta.newKid`); records carry `sigKid`. Verification trusts only the first record's kid a priori and extends trust exclusively along handoff records — an unintroduced kid breaks the chain. Legacy records (no `sigKid`) hash identically to before.
2. **Merkle checkpoints.** RFC 6962-style roots over record hashes, signed, cut every `checkpoint_interval` records and on demand. Exports bundle records + checkpoints; offline verification recomputes roots. An optional anchor webhook (`TOOLGATE_ANCHOR_URL`) POSTs each checkpoint to an external witness — with an anchored checkpoint, rewriting history requires compromising Toolgate *and* the witness *and* the timeline.

## Consequences

`audit verify` now reports chain + checkpoint validity; the offline verifier accepts JWKS and enforces lineage. Full Rekor/Tessera inclusion-proof integration stays open (#12); the webhook is the sink where it plugs in.
