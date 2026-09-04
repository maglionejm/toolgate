## 1. Harness
- [x] 1.1 `tests/redteam/conftest.py`: attacker fixtures (stolen token, stolen key+token, malicious operator, MCP-only client)
- [x] 1.2 CI job `redteam` in ci.yml (separate from `checks`)

## 2. Attack modules
- [x] 2.1 `test_mcp_theft.py` — blast radius, revocation latency
- [x] 2.2 `test_rotation_forgery.py` — forged/stripped/self-introduced handoffs vs offline verify
- [x] 2.3 `test_taint_evasion.py` — txn splitting, re-exchange laundering
- [x] 2.4 `test_approval_argswap.py` — decide/execute race variants, expired-claim reuse
- [x] 2.5 `test_tenant_isolation.py` — cross-tenant upstream/approval/audit probes
- [x] 2.6 `test_concurrency.py` — budget + approval claim races (asyncio.gather)

## 3. Findings policy
- [x] 3.1 Document adversary models + accepted risks in docs/SECURITY.md
- [x] 3.2 File one issue per unresolved finding before merging the suite
