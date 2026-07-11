# SPEC-WITNESS-NODE-1 — Deployable HTTP witness node (`tc-witness serve`)

> **apatch artifact:** `spec:SPEC-WITNESS-NODE-1`
> Status: **draft** · 2026-07-11 · Scope: `trustchain` (tc-witness CLI, witness
> protocol) + deploy artifacts. Follow-up to SPEC-CHAIN-INTEGRITY-1 R4 (witness
> independently recomputes RFC 6962 consistency).

The witness protocol exists (ADR-SEC-006: `SignedTreeHead` / `CoSignedTreeHead`,
`Witness.observe`, quorum verification) and the Platform log client speaks it
(`audit_witness.anchor` POSTs an STH and verifies the returned co-signature
quorum against trusted keys). What is missing is the **deployable unit**: a bank
must be able to run a witness in a *second trust domain* — another team, another
datacenter, another org — with one systemd unit or docker-compose file. Without
that, "independent witness" is a protocol, not a product.

Threat model of record (same as SPEC-CHAIN-INTEGRITY-1): the **log operator
holds the log signing key and controls the database**. The witness's job is to
make retroactive rewrite/fork of the log impossible without collusion, and its
memory (last observed tree head per log) is the anchor of that guarantee.

**Every change must be non-breaking**: the existing file-based CLI
(`init`/`observe`/`verify`/`quorum`) and the current Platform client wire format
(bare STH POST → CoSignedTreeHead JSON) keep working unchanged.

---

## R1 — `tc-witness serve`: HTTP witness node (stdlib-only)

A new `serve` subcommand runs a long-lived witness over HTTP:

- `GET /healthz` → `{ok, witness_id, public_key}` (b64 raw Ed25519).
- `GET /observed?log_id=<id>` → the witness's last observation
  `{log_id, tree_size, root_hash, observed_at}` or 404 — lets a log operator
  build a consistency proof anchored at the witness's own memory.
- `POST /observe` (also `POST /` for stub compatibility) — body is either a
  **bare STH** dict (current Platform client) or an **envelope**
  `{"sth": {...}, "consistency": {"old_tree_size": N, "old_root_hash": H,
  "proof": [hex...]}}`.
- Responds `200` with `CoSignedTreeHead.to_dict()` JSON on co-sign; `4xx` with
  `{error}` on refusal. Refusals never mutate state.

Constraints: stdlib `http.server.ThreadingHTTPServer` only (no new runtime
deps); state mutations behind a lock; state file written atomically
(tmp+rename); key file format is the existing `tc-witness init` JSON.

(verify: pytest tests/test_witness_serve.py)

## R2 — refusal rules: anti-rollback, anti-fork, key pinning, consistency

The serve node enforces, per `log_id`, against its persisted state:

1. **Invalid log signature** on the STH → 400 (never co-sign).
2. **Log-key pinning.** `--log-pubkey <b64>` (repeatable) pins the accepted log
   keys explicitly; without it, the key seen at first observation is pinned
   (TOFU) and any later STH from a different key → 409 `log key changed`.
3. **Shrink**: `tree_size < last.tree_size` → 409.
4. **Fork**: `tree_size == last.tree_size` with a different `root_hash` → 409.
   Same size + same root → co-sign again (idempotent re-anchor).
5. **Growth** (`tree_size > last.tree_size`):
   - if the envelope carries a consistency proof, its `old_tree_size` /
     `old_root_hash` MUST equal the witness's own remembered values (proofs are
     anchored at the witness's memory, not at what the operator claims), and
     `rfc6962.store_verify_consistency` must pass → otherwise 409;
   - with `--require-consistency`, growth **without** a proof → 409 (the
     recommended bank profile);
   - without the flag, proof-less growth is accepted with anti-rollback checks
     only (compatibility with the legacy `{merkle_root, length}` clients).

(verify: pytest tests/test_witness_serve.py)

## R3 — deploy artifacts: witness as a unit in a second trust domain

`deploy/witness/` ships:

- `Dockerfile` + `docker-compose.yml` — `pip install trustchain`, key/state on
  a mounted volume, `tc-witness serve` entrypoint, healthcheck on `/healthz`.
- `trustchain-witness.service` — systemd unit (Restart=always, state dir).
- `README.md` — key ceremony (`tc-witness init` **on the witness host**; the
  private key never leaves it), what to hand the log operator (witness id +
  public key for `TC_AUDIT_WITNESS_PUBKEYS`), Platform env wiring
  (`TC_LOG_STH_KEY`, `TC_AUDIT_WITNESS_URL`, `TC_AUDIT_WITNESS_QUORUM`), and
  the operational rule that the witness's `observed.json` is the anchor of the
  no-rewrite guarantee (back it up independently of the log operator).

(verify: docker compose config -q in deploy/witness + README review)

## R4 — Platform client upgrade (cross-repo, TrustChain_Platform)

`audit_witness.anchor` gains an optional consistency path: fetch
`GET /observed?log_id=`, and when the witness has prior state, include the
log's `consistency_proof(old_size, old_root)` in the envelope so a
`--require-consistency` witness accepts. Bare-STH behavior unchanged when the
witness has no memory or the endpoint is absent (legacy stub). Implemented and
attested in the Platform repo; tracked here for the cross-repo picture.

(verify: Platform backend/tests — witness anchor tests)
