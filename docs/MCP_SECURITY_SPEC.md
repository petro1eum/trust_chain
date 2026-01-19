# MCP Security Specification v1.0

**Status:** Draft  
**Authors:** Ed Cherednik  
**Date:** January 2026

---

## Abstract

This specification defines security requirements for running Model Context Protocol (MCP) servers in production environments. It establishes cryptographic verification as a mandatory component for all MCP tool executions and provides a reference implementation via TrustChain.

---

## 1. Introduction

### 1.1 Problem Statement

MCP enables AI assistants like Claude to call external tools. However, the protocol provides no built-in mechanism to:

- Prove that a tool response came from actual execution (not hallucination)
- Detect tampering between tool execution and response delivery
- Prevent replay attacks where old responses are resubmitted
- Establish audit trails for compliance requirements

**Without cryptographic verification, MCP deployments are vulnerable to:**

| Attack Vector | Impact | Without Verification |
|---------------|--------|---------------------|
| Response Injection | AI uses forged data | Undetectable |
| Replay Attack | Duplicate actions (e.g., payments) | Undetectable |
| Tampering | Modified results | Undetectable |
| Non-repudiation | No proof of execution | Impossible |

### 1.2 Scope

This specification covers:

- Cryptographic signing of MCP tool responses
- Nonce-based replay protection
- Chain of Trust for multi-step operations
- Key management and rotation
- Audit trail requirements

---

## 2. Terminology

| Term | Definition |
|------|------------|
| **Verifiable Execution Proof** | Cryptographic signature proving tool execution authenticity |
| **Execution Graph** | DAG of signed operations linked by parent signatures |
| **Nonce** | One-time value preventing response replay |
| **Chain of Trust** | Sequence of cryptographically linked operations |

---

## 3. Security Requirements

### 3.1 MUST Requirements

MCP servers in production **MUST**:

1. **Sign all tool responses** with Ed25519 or equivalent (128-bit security level minimum)
2. **Include nonce** in every response for replay protection
3. **Include timestamp** with maximum clock skew tolerance of 5 minutes
4. **Provide public key export** for external verification
5. **Reject replayed nonces** within the TTL window (default: 24 hours)

### 3.2 SHOULD Requirements

MCP servers **SHOULD**:

1. Support Chain of Trust via `parent_signature` field
2. Provide key rotation mechanism
3. Expose metrics for security monitoring
4. Support distributed nonce storage for horizontal scaling

### 3.3 MAY Requirements

MCP servers **MAY**:

1. Implement policy-based access control
2. Support hardware security modules (HSM)
3. Integrate with enterprise key management systems

---

## 4. Message Format

### 4.1 Signed Response Schema

```json
{
  "tool_id": "string",
  "data": "any",
  "signature": "base64_ed25519_signature",
  "signature_id": "uuid",
  "timestamp": 1737320400.123,
  "nonce": "uuid",
  "parent_signature": "base64_ed25519_signature | null"
}
```

### 4.2 Canonical Serialization

For signature computation, responses MUST be serialized as:

```json
{"data":...,"nonce":"...","parent_signature":...,"timestamp":...,"tool_id":"..."}
```

Keys sorted alphabetically, no whitespace, UTF-8 encoding.

### 4.3 Signature Algorithm

```
signature = Ed25519_Sign(private_key, SHA256(canonical_json))
```

---

## 5. Key Management

### 5.1 Key Generation

- Keys MUST be generated using cryptographically secure random source
- Key IDs SHOULD be derived from public key hash (first 16 bytes)
- Private keys MUST NOT be logged or exposed in responses

### 5.2 Key Storage

```json
{
  "type": "ed25519",
  "key_id": "uuid",
  "private_key": "base64_encoded",
  "created_at": 1737320400,
  "algorithm": "ed25519"
}
```

### 5.3 Key Rotation

- Rotation MUST generate entirely new key pair
- Old signatures remain valid for verification (with old public key)
- Rotation timestamp MUST be recorded for audit

---

## 6. Replay Protection

### 6.1 Nonce Requirements

- Nonces MUST be UUIDv4 or equivalent (128-bit minimum entropy)
- Nonce storage MUST persist for TTL duration
- Distributed systems MUST use shared nonce storage (e.g., Redis)

### 6.2 Verification Flow

```
1. Receive response with nonce
2. Check if nonce exists in storage
3. If exists: REJECT (replay attack)
4. If not exists: ADD to storage with TTL
5. Proceed with signature verification
```

---

## 7. Chain of Trust

### 7.1 Linking Operations

Multi-step operations MUST be linked via `parent_signature`:

```
Step 1: search     → signature_1
Step 2: analyze    → signature_2, parent = signature_1
Step 3: report     → signature_3, parent = signature_2
```

### 7.2 Chain Verification

1. Verify each signature independently
2. Verify parent_signature chain is unbroken
3. Verify temporal ordering (timestamps ascending)

---

## 8. Reference Implementation

### 8.1 TrustChain Library

TrustChain provides a complete implementation of this specification:

```bash
pip install trustchain[mcp]
```

### 8.2 Usage

```python
from trustchain import TrustChain
from trustchain.integrations.mcp import serve_mcp

tc = TrustChain()

@tc.tool("database_query")
def query(sql: str) -> list:
    return execute_query(sql)

serve_mcp(tc)  # All responses automatically signed
```

### 8.3 Verification

```python
from trustchain.v2.verifier import TrustChainVerifier

verifier = TrustChainVerifier(public_key)
assert verifier.verify(response)
```

---

## 9. Compliance Mapping

| Standard | Covered Requirements |
|----------|---------------------|
| SOC2 | CC6.1, CC6.6, CC7.2 |
| ISO 27001 | A.10.1, A.12.2, A.18.1 |
| HIPAA | 164.312(c), 164.312(e) |
| EU AI Act | Art. 14, Art. 17 |

---

## 10. Security Considerations

### 10.1 Threat Model

| Threat | Mitigation |
|--------|------------|
| Key compromise | Regular rotation, HSM support |
| Storage exhaustion | TTL-based nonce expiration |
| Timing attacks | Constant-time comparison |
| Man-in-the-middle | TLS + signature verification |

### 10.2 Limitations

- Does not protect against compromised tool implementation
- Requires secure key storage (out of scope)
- Clock synchronization required for distributed deployments

---

## 11. Future Work

- **Phase 13:** Policy Layer (YAML-based deny/allow/require)
- **Phase 14:** Execution Graph (DAG analysis, fork detection)
- **Phase 15:** Hardware attestation integration

---

## Appendix A: Test Vectors

### A.1 Signing

```
tool_id: "test"
data: {"value": 42}
timestamp: 1737320400.0
nonce: "550e8400-e29b-41d4-a716-446655440000"
parent_signature: null

Expected canonical JSON:
{"data":{"value":42},"nonce":"550e8400-e29b-41d4-a716-446655440000","parent_signature":null,"timestamp":1737320400.0,"tool_id":"test"}

SHA256 hash:
0x7a8b9c...
```

---

## References

- [MCP Specification](https://modelcontextprotocol.io/specification)
- [Ed25519 Algorithm (RFC 8032)](https://tools.ietf.org/html/rfc8032)
- [CloudEvents Specification](https://cloudevents.io/)
- [TrustChain Documentation](https://github.com/petro1eum/trust_chain)
