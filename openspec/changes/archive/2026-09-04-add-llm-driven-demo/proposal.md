# Demo v2: a real LLM agent driving gated tools

## Why
GitHub issue: #22. The six-act demo is scripted: convincing about the gate, silent about the point — that a *real, promptable* agent gets contained. A live LLM loop turns the demo into the sales asset: watch an actual model attempt an injected exfiltration and get parked by taint policy.

## What Changes
- `toolgate demo --live`: an agent loop driven by the Anthropic API (latest model, key via ANTHROPIC_API_KEY) using `toolgate.integrations` tool dispatch against the same mock upstreams.
- Act 7 — prompt-injection containment: the mock browse tool returns a hostile page instructing exfiltration via email; the taint rule parks the attempt; the transcript shows the model trying and the gate refusing.
- Offline behavior unchanged: without an API key the current scripted demo runs (CI stays hermetic); `--live` without a key exits with guidance.

## Impact
- Affected specs: demo (new)
- Affected code: demo.py (+ live module), optional extra `toolgate-io[demo]` for the anthropic SDK, portal/README copy
