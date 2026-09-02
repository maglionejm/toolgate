# ADR 0003: Node + Hono + node:sqlite for the MVP

**Status**: accepted · 2026-09-02

## Context

MVP needs: fast iteration, single-binary-ish deploy (Cloud Run later), zero native-module friction, and a storage layer that can be swapped for Postgres when multi-instance.

## Decision

- **Node 26 + TypeScript** (strict, `verbatimModuleSyntax`), pnpm workspaces, internal-packages pattern (exports point at `src/`, run via `tsx`, no build step for private packages).
- **Hono** for HTTP: tiny, standards-based (Fetch API), trivially portable to Cloud Run/Workers/Lambda.
- **node:sqlite** (`DatabaseSync`): built into Node — no native compilation, synchronous (fine at MVP scale), one file per environment. All access goes through a `Store` class so the swap to Postgres is mechanical.
- **Crypto**: `jose` for JWK/JWT, `node:crypto` for hashing/raw Ed25519 signatures (audit chain), AES-256-GCM for the vault.

## Consequences

- One process can host both control plane and gate in the MVP (mounted on `/v1/control` and `/v1/gate`); they share the store but only communicate through domain interfaces, preserving the future split into separate services.
- Single-writer SQLite limits horizontal scale; acceptable until post-MVP Postgres migration (tracked in backlog).
