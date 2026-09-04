# Contributing

Thanks for your interest in Toolgate. The project is early and moving fast; this keeps contributions frictionless for everyone.

## Workflow

- **Everything goes through issues and pull requests.** No direct pushes to `main`.
- Open or claim an issue before large changes — the [issue tracker](../../issues) is the roadmap.
- Roadmap issues are spec-driven: each maps to a change package under [`openspec/changes/`](openspec/changes/) (proposal, normative requirements with scenarios, task checklist). Validate edits with `npx @fission-ai/openspec validate --all`. Implement against the spec; archive the change package when it ships.
- Branch from `main`, keep PRs focused, and reference the issue (`Closes #N`).
- CI must be green: `ruff check` + the full test suite.

## Development setup

```bash
uv sync
uv run ruff check src tests
uv run pytest tests/ -q
uv run toolgate-demo        # end-to-end sanity
```

## Ground rules

- **Security-sensitive code** (`toolgate/core/token.py`, `toolgate/core/assertion.py`, `toolgate/core/audit.py`, the gate pipeline) requires tests for every behavior change — including the negative cases (theft, replay, tamper).
- The wire format (camelCase fields, token claims, endpoints) is a compatibility surface; changes to it need an ADR in `docs/adr/`.
- New behavior ships with documentation (`docs/`), not just code.
- No credentials, tokens, or real endpoints in code, tests, fixtures, or issue text — ever.
- Never stage local runtime state: databases and their sidecars (`*.db`, `*.db-wal`, `*.db-shm`), `.toolgate.env`, key files. Prefer explicit `git add <paths>` over `git add -A`.

## Reporting security issues

Do **not** open public issues for exploitable findings — see [SECURITY.md](SECURITY.md).

## License

By contributing you agree that your contributions are licensed under the [Apache License 2.0](LICENSE).
