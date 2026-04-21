# RFC: MCP Tool Result Signing

**Status:** Draft  
**Author:** Ed Cherednik  
**Created:** 2026-04-21  
**Requires:** MCP Protocol v1.0+  

## Abstract

This document proposes an extension to the Model Context Protocol (MCP) for
cryptographic signing of tool execution results. The extension enables clients
to distinguish genuine tool outputs from hallucinated or tampered data using
Ed25519 digital signatures and X.509 certificate chains.

## Motivation

MCP tool responses are currently unsigned. When an LLM reports data "from a
tool," there is no cryptographic proof that:

1. The tool was **actually executed** (vs. hallucinated)
2. The response was **not tampered with** in transit
3. The response came from a **specific, identifiable** tool server

This creates a trust gap in high-stakes applications (finance, healthcare,
legal, procurement) where the distinction between "real data" and
"plausible-sounding hallucination" has material consequences.

## Specification

### Signed Result Format

Tool results MAY include signing metadata alongside standard MCP content:

```json
{
  "content": [
    {
      "type": "text",
      "text": "{\"price\": 45000, \"currency\": \"RUB\", \"quantity\": 200}"
    }
  ],
  "__trustchain_signature__": "base64-encoded-ed25519-signature",
  "__trustchain_key_id__": "agent-sales-01",
  "__trustchain_cert_fingerprint__": "SHA256:a7b3c9f2...",
  "__fact_manifest__": [
    {
      "path": "price",
      "value": "45000",
      "value_type": "number",
      "label": "Price",
      "unit": "RUB",
      "critical": true
    },
    {
      "path": "quantity",
      "value": "200",
      "value_type": "number",
      "label": "Quantity",
      "critical": true
    }
  ]
}
```

### Signature Coverage

The signature MUST cover:
- The `content` array (serialized as canonical JSON)
- The `__fact_manifest__` array (if present)
- A monotonic timestamp or nonce (replay protection)

The signature MUST NOT cover:
- Transport-layer metadata
- MCP protocol framing

### Fact Manifest

The `__fact_manifest__` array enables **granular verification** — clients can
identify exactly which data points are cryptographically attested:

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `path` | string | yes | JSON path to the attested value |
| `value` | string | yes | The attested value (string-encoded) |
| `value_type` | string | yes | "string", "number", "boolean" |
| `label` | string | no | Human-readable label for display |
| `unit` | string | no | Unit of measurement |
| `critical` | boolean | no | If true, clients SHOULD alert when missing |
| `tool_id` | string | no | Identifier of the specific tool |

### Trust Model

Signing keys are bound to X.509 certificates issued by a Certificate Authority
(CA). This is the same trust model used by TLS/HTTPS:

```
Root CA (trust anchor, pinnable)
  └── Platform CA (intermediate, rotatable)
        └── Agent Certificate (Ed25519, per-agent)
```

Clients verify signatures by:
1. Obtaining the agent's X.509 certificate from a public registry
2. Verifying the certificate chain against a known Root CA
3. Extracting the Ed25519 public key from the certificate
4. Verifying the signature over the tool result content

### Public Registry

A conforming implementation SHOULD provide public endpoints:

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/agents` | GET | List registered agents (minimal metadata) |
| `/agents/{id}/cert` | GET | Download agent X.509 certificate (PEM) |
| `/ca` | GET | Download intermediate CA certificate |
| `/root-ca` | GET | Download root CA certificate |
| `/crl` | GET | Certificate Revocation List |
| `/verify` | POST | Online signature verification |

### Client Behavior

Clients (e.g., LLM applications, chat UIs) SHOULD:

1. **Display verification status** — visual indicator (badge, shield) when
   tool results carry valid signatures
2. **Surface fact manifests** — show which specific data points are attested
3. **Check CRL** — periodically verify that agent certificates are not revoked
4. **Alert on missing critical facts** — if a `critical: true` manifest entry
   is absent from the LLM's response, highlight this discrepancy

Clients MAY:
- Cache CA certificates (they change infrequently)
- Perform offline verification (no server call needed after cert download)
- Display a badge linking to a public verification page

## Security Considerations

- **Replay protection**: Implementations MUST include a timestamp or nonce in
  the signed payload. Servers SHOULD reject signatures older than a
  configurable window (default: 5 minutes).
- **Key compromise**: The CRL mechanism provides revocation capability. Agents
  with compromised keys can be revoked, and all subsequent signatures from
  that key should be rejected.
- **Trust anchor distribution**: Root CA certificates should be distributed
  via secure channels (HTTPS, package managers) and pinned by clients.

## Reference Implementation

The TrustChain library (`pip install trustchain`, MIT license) provides a
complete implementation of this specification:

- **OSS**: Ed25519 signing, Merkle audit log, CLI tools
- **Pro**: FactSeal v2 (manifest-inside-signature), PolicyEngine, TSA
- **Platform**: X.509 CA, public registry, embeddable badge

GitHub: https://github.com/petro1eum/trust_chain  
PyPI: https://pypi.org/project/trustchain/  
Public Registry: https://keys.trust-chain.ai

## Copyright

This document is placed in the public domain.
