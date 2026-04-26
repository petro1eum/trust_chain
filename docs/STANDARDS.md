# TrustChain Standards and Positioning

TrustChain is not isolated from the emerging AI trust ecosystem.

The category now includes agent receipts, SCITT profiles, W3C Verifiable
Credentials, MCPS envelopes, Sigstore/in-toto attestations, and hash-chained
audit products. TrustChain's position is practical interoperability:

> Native `.tcreceipt` evidence first, standards exports second.

## Functional Map

| Layer | OSS capability | Paid / enterprise boundary |
|-------|----------------|----------------------------|
| Signed facts | `SignedResponse`, Ed25519, nonce, timestamp | KMS/HSM custody and policy |
| Portable proof | `.tcreceipt`, offline verification | Compliance reports and team workflows |
| Execution chain | `.trustchain/`, `tc log`, `tc chain-verify` | Dashboards, retention, custody |
| Standards export | SCITT JSON, W3C VC, in-toto Statement | COSE/SCITT admission, transparency service |
| Anchoring | `tc anchor export` / `verify` | Scheduled anchoring, external evidence store |
| Tool identity | tool certificates and PKIX primitives | registry, revocation workflows, SSO |

## OSS Standards Adapters

```python
from trustchain.standards import (
    to_scitt_air_json,
    to_w3c_vc,
    to_intoto_statement,
)

air = to_scitt_air_json(
    signed_response,
    agent_id="agent:researcher",
    sequence_number=3,
)

vc = to_w3c_vc(
    receipt,
    issuer="did:web:trust-chain.ai",
    subject_id="did:example:agent",
)

statement = to_intoto_statement(signed_response)
```

## CLI Export

```bash
tc standards export result.tcreceipt --format scitt -o result.air.json
tc standards export result.tcreceipt --format w3c-vc -o result.vc.json
tc standards export result.tcreceipt --format intoto -o result.intoto.json
```

## SCITT

Module: `trustchain.standards.scitt`

Output: AIR-shaped JSON profile with:

- `content_hash`
- `prev_chain_hash`
- `chain_hash`
- `sequence_number`
- `action_timestamp_ms`
- `agent_id`

This is not a COSE_Sign1 transparency receipt. It is a deterministic JSON
profile designed to be wrapped or admitted by a SCITT-capable custody layer.

## W3C Verifiable Credentials

Module: `trustchain.standards.w3c_vc`

Output: VC-shaped JSON object embedding the native `.tcreceipt` in
`credentialSubject.receipt`.

The native TrustChain signature remains the source of truth. The VC proof fields
describe the native signature scope; they do not claim to sign the outer VC JSON.

## in-toto / Sigstore

Module: `trustchain.standards.intoto`

Output: in-toto Statement v1.0 with:

- TrustChain subject digest
- TrustChain predicate type
- embedded signed response envelope

This lets AI execution evidence enter supply-chain tooling such as DSSE, cosign,
policy engines, and artifact attestations.

## Alternatives and Overlap

| Project / standard | Overlap | TrustChain angle |
|--------------------|---------|------------------|
| Signet | Signed MCP tool calls, Ed25519 receipts, hash chain | TrustChain covers tool outputs, `.tcreceipt`, Tool PKI, broader SDK and tiers |
| Agent Receipts | W3C VC-based agent action receipts | TrustChain can export VC-shaped receipts while keeping native receipts simple |
| SCITT AI Agent Execution | Evidence records, transparency service, chain hash | TrustChain can be the SDK that emits SCITT-ready evidence |
| MCPS | Signed MCP envelopes and passports | TrustChain complements message security with durable output evidence |
| Sigstore / in-toto | Signed supply-chain attestations | TrustChain exports AI execution evidence into that ecosystem |
| ChainProof / ProofTrail | Hash-chained or Merkle audit trails | TrustChain adds signing, receipts, Tool PKI, and offline verification |

## Positioning

TrustChain does not claim that Ed25519, hash chains, or receipts are novel.
The product value is packaging those primitives into a usable AI execution trust
layer:

- developer-friendly Python API;
- portable `.tcreceipt`;
- file/Postgres chain storage;
- browser and CLI verification;
- standards exports;
- anchoring path;
- Tool PKI and registry path;
- OSS to Pro to Enterprise adoption model.

## Related Pages

- Receipt format: `docs/RECEIPTS.md` / `docs/receipts.html`
- Tool PKI: `docs/TOOL_PKI.md` / `docs/tool-pki.html`
- Compliance evidence: `docs/COMPLIANCE.md` / `docs/compliance.html`

## Public HTML

For website visitors:

- `docs/receipts.html`
- `docs/standards.html`
- `docs/tool-pki.html`
- `docs/compliance.html`
- `docs/technology.html`
