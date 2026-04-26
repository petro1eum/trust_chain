# TrustChain Compliance Evidence

TrustChain provides technical evidence primitives for AI compliance programs.

It does not make a system compliant by itself. It helps teams produce
cryptographically verifiable records that support compliance review, incident
response, auditor evidence, and customer trust.

## What TrustChain Provides

| Evidence | Purpose | Tier |
|----------|---------|------|
| Signed response | Prove origin and integrity of a tool output | OSS |
| `.tcreceipt` | Portable proof for offline third-party verification | OSS |
| ChainStore | Ordered execution trail | OSS |
| `tc chain-verify` | Detect broken links and tampering in local chain | OSS |
| `tc anchor` | Store chain-head checkpoint outside the writable chain | OSS |
| Standards export | SCITT-shaped JSON, W3C VC, in-toto Statement | OSS |
| Tool PKI | Bind outputs to certified tool implementations | OSS + Enterprise |
| Reports / dashboards | Auditor-readable evidence packages | Pro |
| Registry / CRL / KMS / HSM | Organizational trust and custody | Enterprise |

## EU AI Act Mapping

| Article | Need | TrustChain evidence |
|---------|------|---------------------|
| Art. 9 | Risk management | Policy hooks, Pro PolicyEngine, signed policy decisions |
| Art. 12 | Automatic logging | Signed responses, ChainStore, `.tcreceipt`, anchors |
| Art. 13 | Transparency | Receipts, standards exports, public verifier, registry metadata |
| Art. 14 | Human oversight | Reports, policy decisions, revocation, dashboards |
| Art. 15 | Cybersecurity | Ed25519, nonces, Tool PKI, X.509, CRL, KMS/HSM path |
| Art. 17 | Quality management | Evidence bundles, retention, reports, incident artifacts |

## Commands

```bash
tc receipt verify result.tcreceipt --pin BASE64_PUBLIC_KEY
tc chain-verify -d .trustchain
tc anchor export -d .trustchain -o chain.anchor.json
tc anchor verify chain.anchor.json -d .trustchain
tc standards export result.tcreceipt --format scitt -o result.air.json
tc standards export result.tcreceipt --format w3c-vc -o result.vc.json
tc standards export result.tcreceipt --format intoto -o result.intoto.json
tc-verify trustchain_chain.jsonl.gz --pubkey BASE64_PUBLIC_KEY
```

## Control Families

| Control family | TrustChain artifact | Still required |
|----------------|---------------------|----------------|
| Integrity | Signature, canonical envelope, receipt verification | Key/runtime protection |
| Traceability | Chain, timestamps, parent signatures | Fail-closed event capture policy |
| Retention | Receipts, chain exports, anchors | Immutable storage and retention policy |
| Identity | Public key pinning, X.509, CRL, registry | Enrollment and ownership review |
| Auditability | CLI verification, reports, bundles | Access control and incident process |

## Limits

- A valid signature proves origin and integrity of bytes, not truth.
- A local chain is tamper-evident, not globally tamper-proof, unless anchored.
- Receipts without pinned keys prove internal consistency, not organizational
  identity.
- Regulatory compliance depends on deployment, controls, documentation, and
  legal interpretation.

## Public HTML

Website page: `docs/compliance.html`.
