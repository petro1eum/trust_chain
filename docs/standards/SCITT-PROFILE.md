# TrustChain ↔ SCITT / CT interoperability profile (v0 draft)

> Status: **v0 draft for community feedback** — 2026-07. Intended next step
> (maintainer decision): submit as an Internet-Draft
> (`draft-trustchain-scitt-agent-receipts`) to the IETF SCITT WG.
>
> Purpose: define how TrustChain artifacts map onto the IETF **SCITT**
> architecture (Supply Chain Integrity, Transparency and Trust) and **RFC
> 9162** (Certificate Transparency v2) concepts, so that a `.tcreceipt`
> produced today remains verifiable inside the emerging standards ecosystem —
> and so that TrustChain is a *profile of* the standards conversation, not a
> competitor to it.

## Why this document exists

Multiple "signed AI-agent receipt" formats are appearing (IETF drafts, ISO
proposals). Most sign on the **vendor's** server. TrustChain's receipts are
signed by the **acting identity** (agent- or tool-held key under a revocable
X.509 certificate), sealed in an RFC 6962 log, co-signed by independent
witnesses, and verifiable offline. This profile pins down the mapping so those
properties survive any format convergence.

## Concept mapping

| TrustChain artifact | SCITT concept | CT (RFC 9162) concept | Notes |
|---|---|---|---|
| `SignedResponse` (canonical JSON, Ed25519, signed fields incl. `signature_id`, `signer_role`, `custody`, `input_hash`, `alg`, `canon`, `parent_signatures`) | **Signed Statement** | — | Issuer = the agent/tool certificate subject; payload = the tool-call envelope. `custody` and `signer_role` become protected-header claims — SCITT has no equivalent today; this is the profile's main contribution |
| Per-agent / per-tool X.509 certificate + CRL | Issuer identity (`did:x509` compatible) | — | Key custody stays with the acting identity — never the transparency service |
| Verifiable log (RFC 6962 MTH, `merkle_scheme=rfc6962`) | **Transparency Service** append-only log | CT log (MTH, §2.1) | Byte-compatible Merkle Tree Hash: 0x00/0x01 domain separation, size-committing root |
| Inclusion proof (`store_verify_inclusion`) | **Receipt** (registration proof) | CT inclusion proof | |
| `SignedTreeHead` + witness `CoSignedTreeHead` quorum | Receipt countersignature / witness ecosystem | STH + (proposed) CT witnesses | TrustChain witnesses **recompute** RFC 6962 consistency against their own memory (`tc-witness serve`, SPEC-WITNESS-NODE-1) — stronger than timestamp-only anchoring |
| `.tcreceipt` bundle | **Transparent Statement** (Signed Statement + Receipt) | — | Self-contained: verifiable offline with PKIX chain + CRL + point-in-time (`--as-of`) validity |
| `tc-verify --strict --as-of` | Verifier profile | CT auditor | Offline, zero trust in log operator *and* vendor |

## Wire-format profile

1. **Today (v3.2)**: canonical JSON over Ed25519. Two canonicalizations,
   selected by the *signed* `canon` field: legacy (sorted-keys/compact/
   ensure_ascii) and `"jcs"` (RFC 8785). The signed `alg` field is the
   algorithm-agility seam.
2. **COSE bridge (planned R)**: emit the same signed fields as a
   `COSE_Sign1` (alg `EdDSA`) with the TrustChain claims in the protected
   header — the encoding SCITT expects. The Ed25519 key, certificate chain,
   and log entry are unchanged; only the envelope encoding differs, so one
   artifact can carry both representations without re-signing ceremony
   changes.

## Verification profile (what a conforming verifier MUST check)

1. Signature over the canonical bytes (per `canon`/`alg`), including all
   attribution fields; unknown extra envelope keys are a **failure** (no
   unsigned rider data).
2. Certificate chain to the pinned root, CRL freshness, and validity **as of
   the signing instant** (revocation-reason aware).
3. RFC 6962 inclusion of the entry under a size-committing root.
4. Witness quorum: k-of-N co-signatures over the same root from keys the
   verifier trusts *independently of the log operator*.
5. All of the above MUST be checkable **offline** from the bundle plus pinned
   trust anchors.

## Non-goals

- Not a claim that `.tcreceipt` is a SCITT Transparent Statement today (the
  COSE bridge is the gap, tracked above).
- Not a semantic-truth attestation: receipts prove **who did what, when,
  under which policy** — not that the model was right (see
  ATTRIBUTION_AND_VALIDITY.md).

## Feedback

Issues/PRs on this repository; the profile will track the SCITT WG documents
(architecture, receipts) as they progress.
