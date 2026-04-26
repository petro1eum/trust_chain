# TrustChain Tool PKI

Tool PKI is TrustChain's identity and code-integrity layer for AI tools.

Most agent receipt systems can show that an agent claimed to call a tool. Tool
PKI adds a stronger guarantee: the output was produced by a certified tool
implementation whose source hash still matches the certificate.

## Why It Matters

Signed output answers:

> Was this payload changed after signing?

Tool PKI answers:

> Was this payload produced by the expected tool implementation?

That distinction matters for regulated agents, financial operations, RAG
pipelines, and any workflow where a compromised or swapped tool is a material
risk.

## Trust Levels

| Level | Issuer | Use case |
|-------|--------|----------|
| Self-signed | Developer / local registry | Development, tests, prototypes |
| Internal CA | Company security team | Private production deployments |
| External CA | Platform or customer-owned authority | Cross-company and regulated verification |

## OSS API

```python
from trustchain.v2.certificate import ToolRegistry, trustchain_certified

registry = ToolRegistry()

def query_customer(customer_id: str) -> dict:
    return {"customer_id": customer_id, "balance": 100}

cert = registry.certify(
    query_customer,
    owner="Risk Engineering",
    organization="Acme Bank",
    permissions=["read:customer"],
)

assert registry.verify(query_customer)

@trustchain_certified(registry)
def guarded_tool(customer_id: str) -> dict:
    return query_customer(customer_id)
```

## Certificate Fields

| Field | Meaning |
|-------|---------|
| `tool_name` / `tool_module` | Callable identity. |
| `version` | Declared tool version. |
| `code_hash` | SHA-256 of normalized source code. |
| `issuer` / `issuer_key_id` | Authority that issued the certificate. |
| `trust_level` | Self-signed, internal, or external. |
| `issued_at` / `expires_at` | Validity window. |
| `revoked` | Immediate shutdown for compromised tools. |
| `permissions` | Declared operations for policy enforcement. |

## Flow

1. Tool author writes a callable.
2. `ToolRegistry.certify()` computes the source hash.
3. A `ToolCertificate` is issued and stored in `.trustchain/certs/`.
4. Runtime verifies the certificate before execution.
5. Tool output is signed and can be wrapped as `.tcreceipt`.
6. The receipt can carry identity/certificate material for third-party checks.

## Relationship To Receipts

| Evidence | Question answered |
|----------|-------------------|
| Signed envelope | Was this output changed after signing? |
| Public key / certificate | Which signer produced it? |
| Tool certificate | Which tool implementation produced it? |
| CRL / revocation | Was that signer or tool revoked? |
| Anchor | Does the chain match a previously published checkpoint? |

## Tier Boundaries

| Tier | Tool PKI role |
|------|---------------|
| OSS | `ToolCertificate`, `ToolRegistry`, code hash checks, local cert store |
| Pro | PolicyEngine, reports, approval workflows, scheduled verification |
| Enterprise | HSM-backed CA, registry, CRL, SSO, retention, custody, support |

## Limits

- Source hash checks do not prove dependencies or runtime are uncompromised.
- Built-ins, lambdas, generated functions, and native extensions may need
  manifest-based hashing.
- A valid tool certificate does not prove the real-world truth of returned data.
- High-assurance deployments should combine Tool PKI with SBOMs, dependency
  pinning, runtime isolation, KMS/HSM, and revocation workflows.

## Public HTML

Website page: `docs/tool-pki.html`.
