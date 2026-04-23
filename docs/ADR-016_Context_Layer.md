# ADR-016 — Context layer (git-like rollback)

## Status

Accepted (design). Реализация поэтапно в `trustchain/v3/`; линейная миграция v2→v3 CAS: **`tc migrate-v3 --apply`** (см. `v3/migration_state.json`).

## Context

Operators need to **undo** mistaken agent/tool actions without losing cryptographic history. A linear `parent_signature` chain proves order but does not give `git revert` semantics.

## Decision

Introduce **v3 object store** (Blob / Tree / Commit / Ref) with:

1. Content-addressable storage `objects/{aa}/{bb}{hash}` for canonical JSON.  
2. **DAG** `parents[]` on `Commit` (merge commits for parallel sub-agents).  
3. **Refs** for branches and named checkpoints.  
4. **Compensating actions** declared on tool manifests (`reverse_tool`).  

## Consequences

- Migration tool `tc migrate-v3` will copy v2 JSON ops into v3 commits (lossless where possible).  
- Storage size grows with snapshots; policy: auto-checkpoint only before “risky” tools unless configured otherwise.

## Auto-checkpoint (политика)

Рекомендуемая политика для агентов: **`checkpoint_policy`**: `always` | `never` | `risky_tools_only`.  
Реализация в рантайме Agent: перед вызовом tool из allow-list risk — неявный `tc checkpoint` / запись в side-channel; в OSS CLI уже есть явный `tc checkpoint` / `tc tag`.  

## Alternatives rejected

- **Soft-delete flags only** — weak audit story; breaks offline verification narrative.  
- **External DB without CAS** — harder for third parties to mirror and verify byte-identical.  
