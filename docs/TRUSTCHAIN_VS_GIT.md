# TrustChain vs Git — honest mapping

TrustChain reuses **Git ergonomics** (`tc log`, `tc status`, `HEAD`, `.trustchain/`) but is **not** a Git reimplementation.

| Git concept | In TrustChain today |
|-------------|---------------------|
| `HEAD` | Points at the latest chain tip (often last signature / Merkle root depending on storage mode). |
| `tc log`, `tc status`, `tc blame`, `tc diff`, `tc show` | Implemented for the **audit chain** of signed tool operations. |
| Blob / tree / commit objects (SHA-1 content) | **v2 file chain:** JSON records keyed by operation id. **v3 (planned):** true CAS `objects/ab/cdef…` — see [ADR-016_Context_Layer.md](ADR-016_Context_Layer.md). |
| DAG commits, merge, branches | **v2:** linear `parent_signature` links. **v3:** DAG + branches + revert — see context-layer ADR. |
| `git clone` / remotes | Not applicable; export signed **JSONL** / reports instead. |
| Index / staging | No staging area; each `sign()` commits an operation (optional Merkle log in verifiable mode). |

**Positioning:** *Signed, verifiable audit trail for AI tools with Git-like CLI* — plus (roadmap) **SSL-for-AI style PKI** and **undo / rollback** for agent actions.
