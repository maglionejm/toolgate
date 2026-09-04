# ADR 0008: Transaction-scoped taint tracking (lethal-trifecta defense)

**Status**: accepted · 2026-09-12

## Context

Per-tool allowlists cannot stop composition attacks: a prompt-injected agent reads untrusted content with an allowed tool, then exfiltrates through another allowed, side-effecting tool. The trifecta (private data + untrusted content + egress) must be broken structurally, not hoped away in the model.

## Decision

Tools declare `contentTrust: "untrusted_source"` when their results carry attacker-influenced content. Successful execution of such a tool taints the call's `txn` (the per-task transaction id already present in every token — this is why it exists). Policy rules gain `when.txnTouchedUntrusted`, so one rule expresses: *browsing is allowed, email is allowed, but both in the same task requires a human*. Coarse binary taint per txn; enforcement at the gate.

## Amendment (2026-09-14)

Red-teaming (#9) proved txn-splitting: a fresh token starts a clean txn, so taint did not follow the delegation. Taint is now recorded per txn **and** per grant; `TOOLGATE_TAINT_SCOPE=grant` makes policies see grant-wide taint, closing the evasion at the cost of coarser blocking. Default remains `txn`; the trade-off is documented in the security model's findings register.

## Consequences

The policy language now speaks about task history, not just single calls. Fine-grained dataflow (which *fields* are tainted) and cross-txn propagation are future work; the simulator supports a `tainted` flag so rules are testable before deployment.
