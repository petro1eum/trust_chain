# Attribution Hardening, Canonicalization & Historical Validity

> Status: v2 · 2026-07-04 · Scope: `trustchain` v2 (signer / receipt / certificate /
> witness / `tc-verify`) + the Platform audit log.
> Companion to [TECHNOLOGY.md](./TECHNOLOGY.md) (§2 sign, §3.2 low-level, §3.10 Tool PKI)
> and [STANDARDS.md](./STANDARDS.md) (canonicalization).

This note documents a series of **strictly additive, backward-compatible**
hardening passes that answer a simple question — *how strong is the attribution
a receipt actually carries?* — plus the operational steps to activate each one.
Unless a feature is explicitly opted into, every existing signature and
`.tcreceipt` document is byte-identical and verifies exactly as before.

Each section names the shipping code and the commit on `bank-fitness-remediation`.

---

## 1. The attribution question

TrustChain's core promise is **attribution**: "this output came from a tool, not
an LLM pretending it did." That promise is only as strong as the guarantee that
**the agent never held the signing pen**. The base primitive —
`sign(tool_id, data)` — took both `tool_id` and `data` from the caller and signed
with a single instance/operator key; `tool_id` was an *unauthenticated string
label*. So a receipt alone could not tell a verifier who signed, how strong the
key custody was, or what input produced the output.

The three headline guarantees (authenticity, integrity, order) are unchanged, and
TrustChain still does **not** guarantee *correctness* (a signed hallucination is a
verifiable hallucination). The passes below let a verifier read the **strength**
of attribution instead of assuming it.

---

## 2. Signed attribution fields  ·  `signer_role` / `custody` / `input_hash` / `alg`

`SignedResponse` gained four optional fields. Each is added to the **signed**
canonical payload **only when set** (like `metadata`/`certificate`/`signature_id`),
so legacy payloads are byte-identical. *(commit `80ebb09`)*

| Field | Meaning | Who sets it |
|---|---|---|
| `signer_role` | `"tool"` (executed) or `"agent"` (self-attested) | caller (honest signed label; the strong, key-backed form is §6) |
| `custody` | `{"type": "software" \| "hard_kms", "key_id", ...}` | **derived from the signer** — a caller cannot forge it |
| `input_hash` | `"sha256:<hex>"` of the canonical request | caller, via `canonical_input_hash(request)` |
| `alg` | signature algorithm id (agility seam) | caller (`None` ⇒ legacy implicit `ed25519`) |

```python
from trustchain.v2.signer import Signer, canonical_input_hash

s = Signer()                                      # or Signer.from_provider(kms)
resp = s.sign(
    "weather_api", {"temp": 21},
    signer_role="tool",
    input_hash=canonical_input_hash({"city": "Berlin"}),   # bind the request
    bind_custody=True,                                     # TRUTHFUL custody
)
assert s.verify(resp)
resp.custody["type"]        # -> "software" | "hard_kms"  (from the signer, not the caller)
```

**Why:** `custody` is computed inside `sign()` from the signer's own state
(`_custody_descriptor()`), so it reflects whether the private seed is in-process
(`software`) or delegated to a hard-KMS/HSM (`hard_kms`) — an auditor reads the
*weight* of the evidence, not a boolean. `input_hash` defeats the classic
attribution-shift (agent feeds a subtly wrong query, the tool honestly signs the
answer *for the wrong input*). All four ride through the `.tcreceipt` envelope
tamper-evidently (`receipt._canonical_envelope_bytes` reuses the signer helper).

---

## 3. Canonicalization

The signed bytes are produced by `_canonical_bytes(canonical_data, canon)` — the
single source of truth used by `sign()`, `verify()`, and the receipt layer.

### 3.1 Cross-implementation correctness  *(commit `47e98f2`)*

The JS SDK's `_canonicalStringify` used `JSON.stringify(obj, Object.keys(obj).sort(), 0)`
— a top-level-only replacer that **silently dropped every nested key** (nested
object → `{}`) and emitted raw UTF-8. So any nested / non-ASCII payload produced a
canonical string that could never verify against the Python reference. It was
replaced with a recursive key sort + `\uXXXX` escaping, byte-identical to Python
`json.dumps(sort_keys=True, separators=(",",":"), ensure_ascii=True)`. A
conformance vector suite (`tests/test_canonicalization_vectors.py`) pins the
scheme and asserts Python↔JS parity.

### 3.2 Opt-in RFC 8785 (JCS)  *(commit `ad88a64`)*

A version-negotiated scheme via an optional **signed** `canon` field:

- absent ⇒ legacy `"json-sort-keys-minified"` (byte-identical to today);
- `"jcs"` ⇒ RFC 8785 JSON Canonicalization Scheme, via the vetted `rfc8785` package.

```python
resp = s.sign("weather_api", {"temp": 21}, canon="jcs")   # sign with JCS
assert s.verify(resp)                                      # verify dispatches on canon
```

Because `canon` is inside the signed payload it **cannot be stripped or
downgraded** (verified by test). JCS was *not* hand-rolled: Python floats diverge
from ES6/JCS in dangerous ways (`1.0`→`1`, `1e-07`→`1e-7`, `-0.0`→`0`), so the
correct implementation requires the library. Install with **`pip install
trustchain[jcs]`**; `canon="jcs"` raises a clear error if it is absent.

### 3.3 No unsigned envelope fields  *(commit `c9ff613`)*

`_canonical_envelope_bytes` covers only a fixed set of known keys, so an **extra**
key in a `.tcreceipt` envelope previously rode along *without* being covered by
the signature — `verify().signature_ok` returned `True` while the envelope carried
attacker-controlled data a consumer might read as trusted. `Receipt.verify()` now
rejects any envelope key outside `_SIGNED_ENVELOPE_KEYS` (`valid=False`;
`signature_ok` stays honest). Forward-compatible: a legitimate new signed field
bumps `RECEIPT_VERSION` and is rejected earlier by the version gate.

---

## 4. Historical (as-of) validity in `tc-verify`  *(commit `e18a000`)*

**Problem:** `tc-verify --strict` checked cert validity at *now* and treated any
CRL entry as unconditionally fatal. With short-lived (1-hour) agent certs, an
honest receipt signed while the cert was valid failed once the cert expired — the
opposite of what a long-lived (courtroom) proof needs.

```
tc-verify … --strict --as-of 2026-07-01T12:00:00Z   # verify as of that instant
tc-verify … --strict --as-of-signing                # derive from the log's own
                                                     # latest signed timestamp
```

With an as-of instant: the cert must have been valid **at that instant** (survives
later expiry); revocation invalidates **only** if dated at/before the instant
**or** the reason is `key_compromise` / `ca_compromise` / `aa_compromise`
(retroactive). **Default (no flag) is unchanged** (validity at *now*, any
revocation fatal). `--as-of-signing` uses the log's *self-asserted* timestamp —
anchor it with a TSA (`tsa_proof`) or a witness (§7) for strong assurance.

---

## 5. Per-tool signing keys — key-backed tool attribution  *(commit `579c614`)*

`signer_role="tool"` (§2) is an honest *label*. The strong form makes it a
**proof**: a tool signs its results with its own Ed25519 key, and the
`ToolRegistry` binds `tool_id → that signing key`.

```python
from trustchain.v2.certificate import ToolRegistry
from trustchain.v2.signer import Signer

registry = ToolRegistry(strict=False)
tool = Signer()                                   # the tool's own key
registry.bind_tool_key("weather_api", tool.get_public_key())

resp = tool.sign("weather_api", {"temp": 21}, signer_role="tool", bind_custody=True)
registry.verify_tool_signature(resp)              # True iff signer_role=="tool"
                                                  #   AND signed by the bound key
```

`verify_tool_signature` returns `True` only when the response's `signer_role` is
`"tool"`, the `tool_id` has a bound key, and the signature verifies against it. It
is built on `signer.verify_with_public_key(response, pubkey)` — a canon-aware
cross-key verifier — so it works for legacy and JCS receipts. An unregistered
tool, an agent self-attestation, or an impostor key all fail.

> The `tool_id → pubkey` binding is currently in-memory (registered at startup);
> persistence is a follow-up.

---

## 6. External witness — operator-cannot-fork  *(commit `01af165`, Platform)*

The `order` guarantee is only as strong as the log being **unforkable by its own
operator**. The OSS `trustchain.v2.witness` module implements a CT-style protocol
(`SignedTreeHead` / `CoSignedTreeHead` / `verify_quorum`, anti-rollback); the
Platform audit log now uses it instead of the previous fire-and-forget POST.

Protocol (`backend/app/services/audit_witness.py`):

1. `build_sth` — the log signs a `SignedTreeHead {log_id, tree_size, root_hash}`.
2. `anchor` — POST the STH to the witness, receive a `CoSignedTreeHead`.
3. `verify_response` — **bind** the co-signature to the exact STH we submitted
   (same `log_id`/`tree_size`/`root_hash`), then `verify_quorum` against a
   configured set of **trusted** witness keys.

`verify_quorum` is secure by construction: a co-signer counts only if its
`witness_id` is in the trusted set **and** its public key equals the trusted key
for that id **and** the co-signature verifies. So an untrusted witness, an
impersonated key, or a co-signature for a forked tree are all rejected (tested).
`log_service.append` fails closed if a witness is required and the quorum does not
verify.

**Activation** requires a deployed witness service plus config — see §8.

---

## 7. Backward-compatibility contract

Every pass follows the same rule that made it safe:

1. New envelope fields default to `None` and enter the canonical payload **only
   when present**; `sort_keys` makes insertion order irrelevant, so a legacy
   object serializes to the exact same bytes → its signature still verifies.
2. `verify()` rebuilds the canonical form from the object's actual fields and
   still tries the `signature_id`-included/omitted vintages; the `canon` field is
   read from the object, so old and new receipts both verify with no dispatch
   change on the caller's part.
3. `tc-verify` validity/revocation gain an optional `as_of`; when `None` (default)
   the path is identical to before.
4. The witness upgrade activates only when a log key + trusted witness keys are
   configured; otherwise the legacy POST is unchanged.

Evidence: the full `tests/` suite is green before and after every pass (same exit
status), plus dedicated tests for each feature (backward-compat, tamper-evidence,
truthful custody, receipt binding, JCS roundtrip/downgrade, unsigned-field
rejection, as-of cases, tool-key proof, witness quorum).

---

## 8. Configuration reference

| Setting | Where | Effect |
|---|---|---|
| `sign(..., signer_role=, input_hash=, alg=, bind_custody=True)` | `Signer`/`TrustChain.sign` | attribution fields (§2) |
| `sign(..., canon="jcs")` + `pip install trustchain[jcs]` | signer | RFC 8785 signing (§3.2) |
| `ToolRegistry.bind_tool_key(tool_id, pubkey)` | certificate | key-backed tool attribution (§5) |
| `tc-verify --as-of <ISO>` / `--as-of-signing` | CLI | historical validity (§4) |
| `TC_LOG_STH_KEY` | Platform | base64 Ed25519 seed for the log's STH key (§6) |
| `TC_AUDIT_WITNESS_PUBKEYS` | Platform | trusted witnesses, `id:b64pubkey` comma list (§6) |
| `TC_AUDIT_WITNESS_QUORUM` | Platform | k-of-N quorum (default 1) (§6) |
| `TC_AUDIT_WITNESS_URL` / `TC_AUDIT_WITNESS_REQUIRED` | Platform | witness endpoint + fail-closed toggle |
| `TC_LOG_ID` | Platform | log identifier (default `platform-audit-log`) |

The strong witness path is active only when **both** `TC_LOG_STH_KEY` and
`TC_AUDIT_WITNESS_PUBKEYS` are set; otherwise the legacy `{merkle_root, length}`
POST is used.

---

## 9. Remaining roadmap

The mechanisms are shipped and tested; these are **operational / follow-up** items:

- **Activate JCS** per deployment (`trustchain[jcs]` dependency) where a published
  standard is preferred over the (now interoperable) default scheme.
- **Deploy a witness service** and provision the log STH key + trusted witness
  keys to make §6 operational in production.
- **Persist per-tool key bindings** (§5 is currently in-memory), ideally folded
  into Tool PKI so a tool's signing key is certified alongside its code hash.
- **TSA verification** — `tsa_proof` (RFC 3161) is carried but not yet verified; a
  verified TSA time would be the strongest anchor for `--as-of`.

---

_Commits on `bank-fitness-remediation`: `80ebb09` (attribution), `e18a000`
(as-of), `47e98f2` (JS canon + docs), `c9ff613` (unsigned-field reject), `ad88a64`
(JCS), `579c614` (per-tool keys); Platform `soc2-type-i-rfp-101` `01af165`
(witness wiring)._
