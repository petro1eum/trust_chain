# TrustChain context layer (git-like rollback) — design

## Goal

Provide a **second layer** beside signatures: a versioned **agent execution context** (tool chain + conversation state) so operators can:

- `checkpoint` — named snapshot  
- `branch` — what-if execution line  
- `revert` / `reset` — roll back to a prior state, using **compensating tool actions** where defined  

## Target object model (v3)

- **Blob** — immutable bytes (canonical JSON, attachments hashes).  
- **Tree** — directory-like snapshot: context window, loaded skills, tool bindings, metadata.  
- **Commit** — `tree` + `parents[]` + message + actor/tool custody refs + signature.  
- **Ref** / **Tag** — named pointers (`refs/heads/main`, `refs/checkpoints/pre-risk`, …).  

## Rollback semantics

- **Revert:** create a new commit that applies `reverse_tool` from a tool manifest (e.g. file restore).  
- **Reset:** move `HEAD` (+ optional hard reset calling reverse tools in order).  
- **Non-reversible ops** must declare `revertible: false` in the tool manifest.  

## Status

Implementation lives under `trustchain/v3/` (incremental). This document is the **contract**; see [ADR-016_Context_Layer.md](ADR-016_Context_Layer.md) for trade-offs and migration from v2 linear chains.

**CLI (incremental):** `tc migrate-v3` / `tc migrate-v3 --apply` — линейная v2-цепь в v3 CAS (`Commit` + `Blob` + `refs/v3/main` + `v3/migration_state.json`). **`tc log --v3`** — обход коммитов от `refs/v3/main`. **`tc show <64-hex>`** — JSON-объект в CAS. **`tc manifest hash <file.json>`** — SHA-256 канона manifest (`tc.manifestHash`). `tc checkpoint` / `tc branch` — `refs/{checkpoints,heads}/`; **`tc checkout <ветка>`** — `HEAD` из `refs/heads/<ветка>.ref`; **`tc reset --soft op_NNNN`** — сдвиг `HEAD`; **`tc log --graph`** — линия по `parent_signature`. `tc refs` — список ref-файлов. Пары **forward→reverse**: `trustchain.v3.compensations` и **`.trustchain/reversibles.json`**. **`tc revert`** — `revert_intent`; undo в рантайме агента.
