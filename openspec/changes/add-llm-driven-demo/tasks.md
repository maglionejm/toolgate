## 1. Live loop
- [x] 1.1 Optional extra `[demo]` (anthropic); lazy import with guidance error
- [x] 1.2 Agent loop: system prompt, integrations dispatch, transcript rendering (same [TAG] format)

## 2. Injection act
- [x] 2.1 Hostile-page fixture on the mock browse tool (contentTrust=untrusted_source)
- [x] 2.2 Taint rule in the demo policy; containment assertions in a live smoke test (skipped without key)

## 3. Polish
- [x] 3.1 README/portal copy for the live demo; docs QUICKSTART note
- [x] 3.2 Deterministic fallback ordering so offline demo output stays byte-comparable in tests
