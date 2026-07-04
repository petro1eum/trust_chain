# Attribution Hardening & Historical Validity

> Status: v1 · 2026-07-04 · Scope: `trustchain` v2 signer / receipt / `tc-verify`
> Companion to [TECHNOLOGY.md](./TECHNOLOGY.md) (§2 sign, §3.2 low-level, §3.10 Tool PKI)
> and [STANDARDS.md](./STANDARDS.md) (canonicalization).

This note documents two backward-compatible hardening passes and the design
reasoning behind them, plus the remaining roadmap. Both passes are **strictly
additive / opt-in**: with the new features unused, every existing signature and
`.tcreceipt` document is byte-identical and verifies exactly as before.

---

## 1. The attribution question

TrustChain's core promise is **attribution**: "this output came from a tool, not
an LLM pretending it did." That promise is only as strong as the guarantee that
**the agent never held the signing pen**. The base primitive —
`sign(tool_id, data)` — takes both `tool_id` and `data` from the caller and signs
with a single instance/operator key; `tool_id` is an *unauthenticated string
label*. So a receipt alone could not tell a verifier:

- **who** actually signed (a tool at its trust boundary vs. an agent self-attesting),
- **how strong** the key custody was (software key in the agent's process vs. HSM/KMS),
- **what input** produced the output (the request was never bound into the signature).

The three headline guarantees (authenticity, integrity, order) remain honest and
unchanged — TrustChain still does **not** guarantee *correctness* (a signed
hallucination is a verifiable hallucination). The hardening below lets a verifier
read the **strength** of attribution instead of assuming it.

---

## 2. Signed attribution fields (opt-in)

`SignedResponse` gained four optional fields. Each is included in the **signed**
canonical payload **only when set** (same rule as `metadata`/`certificate`/
`signature_id`), so `json.dumps(sort_keys=True)` makes legacy payloads
byte-identical.

| Field | Meaning | Who sets it |
|---|---|---|
| `signer_role` | `"tool"` (executed) or `"agent"` (self-attested) | caller (honest, signed label) |
| `custody` | `{"type": "software" \| "hard_kms", "key_id", ...}` | **derived from the signer** — a caller cannot forge it |
| `input_hash` | `"sha256:<hex>"` of the canonical request | caller, via `canonical_input_hash(request)` |
| `alg` | signature algorithm id (seam for future agility) | caller (`None` ⇒ legacy implicit `ed25519`) |

### Usage

```python
from trustchain.v2.signer import Signer, canonical_input_hash

s = Signer()  # or Signer.from_provider(kms_provider) for a hard-KMS key
resp = s.sign(
    "weather_api",
    {"temp": 21},
    signer_role="tool",
    input_hash=canonical_input_hash({"city": "Berlin"}),  # bind the request
    bind_custody=True,   # stamp a TRUTHFUL custody descriptor
)
assert s.verify(resp)                 # unchanged verify path
resp.custody["type"]                  # -> "software" or "hard_kms"
```

### Why this matters

- **`custody` is truthful.** It is computed inside `sign()` from the signer's own
  state (`_custody_descriptor()`), so it reflects whether the private seed is
  in-process (`software`) or delegated to a hard-KMS/HSM (`hard_kms`). A caller
  cannot claim `hard_kms` on a software key. An auditor reads the *weight* of the
  evidence, not a boolean.
- **`input_hash` binds request → response.** It defeats the classic
  attribution-shift: an agent feeds a subtly wrong query ("revenue of ACME
  Holdings" instead of "ACME Corp"), the tool honestly signs the correct answer
  *for the wrong input*, and the blame *looks* like the tool's. With
  `input_hash` a verifier can prove which input produced the signed output.
- **`signer_role`** is an honest, signed label — the strong form (a distinct
  per-tool signing key) is roadmap (§5).

Every field is carried through the `.tcreceipt` envelope
(`receipt._canonical_envelope_bytes` reuses `signer._build_canonical_data`, one
source of truth), so it is tamper-evident: changing `custody` in a receipt
breaks the signature.

---

## 3. Historical (as-of) validity in `tc-verify`

**Problem:** `tc-verify --strict` checked cert validity at *now* and treated any
CRL entry as unconditionally fatal. With short-lived (e.g. 1-hour) agent certs,
an **honest receipt signed while the cert was valid** fails verification once the
cert expires or the serial later appears on a CRL — the opposite of what a
long-lived (courtroom) proof needs.

**Fix (opt-in):**

```
tc-verify … --strict --as-of 2026-07-01T12:00:00Z   # verify as of that instant
tc-verify … --strict --as-of-signing                # derive from the log's own
                                                     # latest signed timestamp
```

Semantics when an as-of instant is supplied:

- **Validity window:** the cert must have been valid **at the as-of instant**
  (`not_before ≤ as_of ≤ not_after`), not now. A signature made while valid
  survives later expiry.
- **Revocation is reason-aware:** a serial on the CRL invalidates the receipt
  **only if** the revocation date is at/before the as-of instant, **or** the
  revocation reason is `key_compromise` / `ca_compromise` / `aa_compromise` —
  key compromise is retroactive because the key may have leaked before the
  recorded date. Other reasons (`superseded`, `affiliation_changed`,
  `cessation_of_operation`, …) do not retroactively void an earlier honest
  signature.

**Caveat — trust of the instant.** `--as-of-signing` uses the log's own
*self-asserted* timestamp. For strong assurance, anchor the instant with a
trusted timestamp (RFC 3161 TSA — the `tsa_proof` field) or an external witness
(`tc-witness`) that independently orders the event; then pass that time via
`--as-of`.

**Default is unchanged.** With neither flag, validity is checked at *now* and any
revocation is fatal — byte-for-byte the prior behavior.

---

## 4. Backward-compatibility contract

Both passes follow the same rule that made them safe:

1. New envelope fields default to `None` and are added to the canonical payload
   **only when present**. `json.dumps(sort_keys=True, separators=(",", ":"))`
   makes insertion order irrelevant, so a legacy object (all new fields `None`)
   serializes to the exact same bytes as before → its signature still verifies.
2. `verify()` rebuilds the canonical form from the object's actual fields and
   still tries the `signature_id`-included/omitted vintages, so both old and new
   receipts verify with no dispatch change.
3. `tc-verify` validity/revocation gain an optional `as_of`; when `None`
   (the default) the code path is identical to before.

Evidence: the full `tests/` suite is green before and after each pass (same
exit status), plus dedicated tests for backward-compat, tamper-evidence,
truthful custody, receipt binding, and each as-of case.

---

## 5. Remaining roadmap (deferred — genuinely breaking or cross-cutting)

These are intentionally **not** shipped here because they cannot be done without
either a versioned envelope migration or cross-repo work:

1. **JCS canonicalization (RFC 8785) + reject-non-canonical.** Today the scheme
   is `json-sort-keys-minified` (`json.dumps(sort_keys=True, separators=(",",":"),
   ensure_ascii=True)`) and `verify()` re-canonicalizes rather than rejecting a
   non-canonical input. Switching to JCS changes the signed bytes for everyone,
   so it needs a **receipt version bump + dual-path verify** (an optional signed
   `canon` field selecting the scheme). The hardest sub-part is ES6/JCS number
   formatting for the `timestamp` float. *A concrete, non-breaking prerequisite —
   fixing the recursive-sort / non-ASCII PY↔JS divergence in the JS SDK
   canonicalizer, plus a conformance vector suite — is shipped alongside this
   note (see `tests/test_canonicalization_vectors.py`).*
2. **Wire `tc-witness` into the Platform write-path.** The CT-style co-signing
   protocol (`SignedTreeHead` / `CoSignedTreeHead` / quorum / anti-rollback)
   exists in OSS but the Platform uses only a fire-and-forget POST of
   `{merkle_root, length}`. Wiring the real counter-signature would deliver
   operator-cannot-fork; it is cross-repo (Platform) network work.
3. **Per-tool signing keys.** The strong form of the tool-vs-agent split: a tool
   signs results with its own key at its trust boundary, so `signer_role="tool"`
   is proven by the key, not merely labeled. Requires per-tool key issuance
   (Tool PKI already certifies tool *code* by hash — this extends it to result
   signing).

---

_See commits `feat(sign): optional signed attribution fields` and
`feat(tc-verify): historical (as-of) validity` on branch
`bank-fitness-remediation`._
