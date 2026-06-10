# Write sandbox (v1)

Protected: `src/**`, `app/**`, `services/**`, `packages/**`, `e2e/**`, `server/**`, `server.js`, `scripts/**`, `docs/specs/**`, `playwright.config.ts`, `vitest.config.ts`.

Allow: `manifests/**`, `tests/**`, `docs/*.md` (narrative, not specs), root `*.md`.

Direct IDE edits and shell mutations are blocked in enforce mode.
Use `apatch_apply_session` / `apatch_execute_next` (MCP) for code and SPEC changes.

Default `watcher: revert` — unleased protected writes are auto-reverted.

Visual inspection: `cursor-ide-browser` MCP is allowed by default (navigate/snapshot — read-only).

Status: `apatch sandbox status --json`

CI: `apatch sandbox ci-gate` (see `.github/workflows/apatch.yml` with `--with-ci`).
