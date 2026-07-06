# SPEC-CHAIN-INTEGRITY-1 — Verifiable-log correctness hardening

> **apatch artifact:** `spec:SPEC-CHAIN-INTEGRITY-1`
> Status: draft · 2026-07-06 · Scope: `trustchain` v2 (merkle / verifiable_log /
> chain_store / witness / tc-verify). Narrative: the 6-agent chain-of-trust code
> review (see [ATTRIBUTION_AND_VALIDITY.md](../ATTRIBUTION_AND_VALIDITY.md)).

The "git for trust" design is sound — entries are Ed25519-signed over a canonical
payload that **includes** the parent link, which is the real differentiator from
git's unsigned Merkle-DAG. But the **verification** layer does not cash the checks
the architecture writes, and the Merkle tree has a genuine malleability bug. This
SPEC tracks the fixes. **Every fix must be non-breaking**: existing signatures and
stored roots must verify unchanged; scheme changes are version-gated / opt-in.

Threat model of record: the **log operator holds the signing key and controls the
database** (the bank case). Tamper-evidence against an outside writer already
holds; these fixes target the operator.

---

## R1 — the Merkle root must commit to the leaf sequence (RFC 6962)

**Defect.** `merkle.py` duplicates the last odd node (Bitcoin-style, `merkle.py:138`)
instead of RFC 6962's split-at-largest-power-of-two, and hashes hex strings not
raw bytes. Consequence (empirically): `root([a,b,c]) == root([a,b,c,c])` — the
root does **not** commit to the leaf count (CVE-2012-2459 class).

**Fix (non-breaking).** Add a correct RFC 6962 implementation
(`trustchain/v2/rfc6962.py`): raw-byte Merkle Tree Hash with 0x00/0x01 domain
separation, inclusion proof + verify, consistency proof + verify — validated
against the RFC 6962 §2.1.3 test vectors. It is a **new module** (nothing depends
on it until opted in), so legacy roots are byte-identical. Adoption by the stores
is version-gated (R5).

(verify: pytest tests/test_rfc6962.py)

## R2 — `chain-verify` re-verifies signatures (or stops claiming it)

**Defect.** `ChainStore.verify` only checks structural links by default; Ed25519
re-verification runs only when `--pubkey` is passed (`chain_store.py:347-367`,
`cli.py:391-395`). But `TRUSTCHAIN_VS_GIT.md:104` claims it "mathematically
verifies every Ed25519 signature … detect if the log was tampered with by hand."
So a hand-edited `data` field with self-consistent links passes the default check.

**Fix (non-breaking).** Re-verify signatures whenever a key is resolvable (stored
key / receipt), surface an explicit "signatures re-verified: yes/no" in the
result, and correct the docs to match reality. Adds capability + honesty; does not
reject anything that was actually valid.

(verify: pytest tests/test_chain_verify_signatures.py)

## R3 — durable `ChainStore.verify` enforces authenticated continuity + DAG parents

**Defect.** `chain_store.py:369-408` is existence-only: a parent need only appear
somewhere earlier, so `op_0003` can skip `op_0002` and still be "valid"; the dead
line `:370` (prev signature fetched then discarded) shows strict continuity was
intended but never wired. The strict linear check lives only in an in-memory
`verify_chain` over a caller-ordered list and ignores `parent_signatures` (DAG).

**Fix (non-breaking).** Add an opt-in `strict=True` to `ChainStore.verify` that
enforces authenticated continuity (each non-root op's parent resolves to its real
predecessor) and validates `parent_signatures` topologically. Default stays
lenient (DAG/orphan-friendly) so nothing existing breaks.

(verify: pytest tests/test_chain_store_strict.py)

## R4 — witness independently verifies a real consistency proof

**Defect.** `consistency_proof()` returns a self-reported `{"consistent": bool}`
recomputed from the log's own current leaves (`verifiable_log.py:414-441`); the
witness **trusts that boolean** (`witness.py:278-282`). The exact operator being
defended against can return `consistent=True` for a rewritten prefix, and a
prefix-rewrite that grows the tree escapes the CLI witness entirely.

**Fix (non-breaking).** Use the R1 compact RFC 6962 consistency proof; the witness
verifies it against `(old_size, old_root, new_size, new_root)` itself rather than
trusting the log. Valid histories still pass; a forged self-report is rejected.

(verify: pytest tests/test_witness_consistency.py)

## R5 — the trusted commitment binds tree size; truncation is caught cryptographically

**Defect.** Tail truncation is caught only by the unsigned `operations_count` meta
field (`tc_verify_main.py:216`, docstring: "naive") under `--strict`, or by the
witness's retained signed `tree_size`. The store's `verify()` compares the
recomputed root only to the co-located HEAD (`verifiable_log.py`), which an
operator rewrites together with the rows.

**Fix (non-breaking).** Make the signed tree head `{size, root}` the trusted
anchor and verify against a signed size, not a bare root/HEAD; authenticate the
tip. Opt-in where a log STH key is configured.

(verify: pytest tests/test_signed_treehead_size.py)

## R6 — the offline auditor verifies the Merkle root + inclusion

**Defect.** `tc_verify_main.py` never touches the Merkle tree/inclusion/consistency
— it verifies only per-op signatures + the `parent_signature` linked list +
`operations_count`. The "CT-grade Merkle log" and the "offline strict auditor" are
disconnected.

**Fix (non-breaking).** Under `--strict`, also recompute the Merkle root (via R1)
from the exported records and compare to the signed tree head; optionally verify
inclusion proofs. Additive; does not change existing exit codes for logs that are
already consistent.

(verify: pytest tests/test_tc_verify_merkle.py)

---

## Priority & sequencing

- **P0 (crypto correctness):** R1 (Merkle commits to size), R4 (real consistency +
  independent witness), R2 (verify actually verifies), R3 (strict continuity).
- **P1 (defence-in-depth):** R5 (signed size / authenticated tip), R6 (unified
  offline auditor).

Order: R1 first (foundation for R4/R6), then R2, R3, R4, R5, R6. Each ships as one
governed, tested, non-breaking commit.

## Non-goals

- Migrating existing stores to RFC 6962 roots (a deployment/migration decision,
  version-gated — this SPEC ships the correct scheme + opt-in wiring, not a forced
  rewrite of historical roots).
- Changing the default trust model or any existing signature's bytes.

> _Notarized under the TrustChain governed workflow · chain-of-trust review 2026-07-06._
