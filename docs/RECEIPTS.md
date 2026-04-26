# TrustChain `.tcreceipt` Specification

`.tcreceipt` is the portable evidence object owned by TrustChain.

It is a self-contained JSON document that lets a third party verify that a tool
output or agent response was signed by a known key. The verifier does not need
access to the original agent, production database, or TrustChain SaaS endpoint.

## Contract

Current stable contract:

| Field | Value |
|-------|-------|
| `format` | `tcreceipt` |
| `version` | `1` |
| Canonicalization | JSON with sorted keys and minified separators |
| Signature algorithm | Ed25519 |
| Base verification | Offline, no network required |

## Minimal Shape

```json
{
  "format": "tcreceipt",
  "version": 1,
  "issued_at": "2026-04-23T14:30:00Z",
  "envelope": {
    "tool_id": "sec_filing_lookup",
    "data": {"company": "Acme", "revenue_usd": 4812300000},
    "signature": "base64-ed25519-signature",
    "signature_id": "uuid",
    "timestamp": 1776954600.12,
    "nonce": "uuid",
    "parent_signature": null
  },
  "key": {
    "algorithm": "ed25519",
    "key_id": "producer-key-id",
    "public_key_b64": "base64-raw-ed25519-public-key"
  },
  "identity": null,
  "witnesses": null,
  "summary": {
    "tool_id": "sec_filing_lookup",
    "timestamp_iso": "2026-04-23T14:30:00Z",
    "signature_short": "abc12345..."
  }
}
```

## Fields

| Field | Required | Meaning |
|-------|----------|---------|
| `format` | yes | Must be `tcreceipt`. |
| `version` | yes | Receipt schema version. Current stable value: `1`. |
| `issued_at` | yes | UTC time when the receipt wrapper was built. |
| `envelope` | yes | The exact TrustChain signed response. This is what the signature covers. |
| `key` | yes | Algorithm, key id, and public key for offline verification. |
| `identity` | no | Optional certificate chain or registry-backed identity metadata. |
| `witnesses` | no | Optional witness co-signatures or custody proofs. |
| `summary` | no | Human-readable helper fields. Not trusted for cryptographic checks. |

## Verification Model

Base verification:

1. Load the receipt.
2. Rebuild the canonical TrustChain envelope.
3. Verify `envelope.signature` with `key.public_key_b64`.
4. Optionally pin the expected public key.
5. Optionally enforce freshness, certificate identity, CRL, or witnesses.

```python
from trustchain import Receipt

receipt = Receipt.load("result.tcreceipt")
result = receipt.verify(expected_public_key_b64=trusted_public_key)
assert result.valid
```

Important distinction:

- Without a pinned key, verification proves the receipt is internally
  consistent: it was signed by the embedded key.
- With a pinned key or verified certificate chain, verification proves the
  receipt came from the expected signer.

## CLI

```bash
tc receipt build signed_response.json --key pubkey.json -o result.tcreceipt
tc receipt show result.tcreceipt
tc receipt verify result.tcreceipt --pin BASE64_PUBLIC_KEY
```

## Standards Export

`.tcreceipt` remains the native source of truth. Standards exports are
interoperability wrappers:

```bash
tc standards export result.tcreceipt --format scitt -o result.air.json
tc standards export result.tcreceipt --format w3c-vc -o result.vc.json
tc standards export result.tcreceipt --format intoto -o result.intoto.json
```

## Anchoring

A local chain is tamper-evident. To make rewrites detectable outside the local
machine, store a chain-head checkpoint somewhere the agent cannot modify:

```bash
tc anchor export -d .trustchain -o chain.anchor.json
tc anchor verify chain.anchor.json -d .trustchain
```

The anchor contains:

- `head`
- `length`
- `chain_sha256`
- `chain_valid`
- optional `merkle_root`

## Limits

TrustChain receipts prove origin and integrity of signed bytes. They do not
prove the real-world truth of the data, the absence of tool compromise, or legal
compliance by themselves.

For high-assurance deployments, combine receipts with pinned identities,
revocation checks, external anchoring, KMS/HSM, and operational controls.

Related:

- Tool PKI: `docs/TOOL_PKI.md` / `docs/tool-pki.html`
- Compliance evidence: `docs/COMPLIANCE.md` / `docs/compliance.html`
- Standards export: `docs/STANDARDS.md` / `docs/standards.html`
