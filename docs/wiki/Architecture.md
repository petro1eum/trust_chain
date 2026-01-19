# Architecture

Technical architecture of TrustChain.

## Overview

TrustChain provides a cryptographic signing layer for AI agent tool calls. Every tool response is signed with Ed25519, creating an immutable audit trail.

```
+-------------------+     +------------------+     +------------------+
|   AI Agent        | --> |   TrustChain     | --> |   Signed Tool    |
|   (LLM/Claude)    |     |   Signing Layer  |     |   Response       |
+-------------------+     +------------------+     +------------------+
                                  |
                                  v
                          +------------------+
                          |   Verification   |
                          |   & Audit Trail  |
                          +------------------+
```

---

## Core Components

### 1. TrustChain Core

The main orchestrator that manages tools, signing, and verification.

```
TrustChain
    |
    +-- Signer (Ed25519)
    |       |
    |       +-- Private Key
    |       +-- Public Key
    |
    +-- NonceStorage
    |       |
    |       +-- Memory Backend
    |       +-- Redis Backend
    |
    +-- Tool Registry
            |
            +-- Tool Definitions
            +-- Schema Generator
```

### 2. Signer

Handles cryptographic operations using Ed25519.

| Operation | Description |
|-----------|-------------|
| `sign()` | Create signature for data |
| `verify()` | Verify signature authenticity |
| `get_key_id()` | Get public key identifier |

### 3. NonceStorage

Prevents replay attacks by tracking used nonces.

| Backend | Use Case |
|---------|----------|
| Memory | Single instance, development |
| Redis | Distributed, production |

---

## Data Flow

### Signing Flow

```
1. Function called
       |
       v
2. Generate nonce (UUID)
       |
       v
3. Create payload:
   - tool_id
   - data (function result)
   - nonce
   - timestamp
   - parent_signature (optional)
       |
       v
4. Sign payload with Ed25519
       |
       v
5. Return SignedResponse
```

### Verification Flow

```
1. Receive SignedResponse
       |
       v
2. Check nonce not used (replay protection)
       |
       v
3. Reconstruct payload from response
       |
       v
4. Verify Ed25519 signature
       |
       v
5. Mark nonce as used
       |
       v
6. Return True/False
```

---

## Chain of Trust

Links operations cryptographically to prove execution order.

```
+------------+     +------------+     +------------+
|  Step 1    |     |  Step 2    |     |  Step 3    |
|  sig: A    | <-- |  sig: B    | <-- |  sig: C    |
|            |     |  parent: A |     |  parent: B |
+------------+     +------------+     +------------+
```

Each step includes the previous step's signature, creating an unbreakable chain.

---

## Merkle Trees

For efficient verification of large documents.

```
                    Root Hash
                   /         \
              Hash 01        Hash 23
             /      \       /      \
         Hash 0   Hash 1  Hash 2  Hash 3
            |        |       |       |
         Chunk 0  Chunk 1 Chunk 2 Chunk 3
```

Benefits:
- Verify any chunk with O(log n) proof size
- Root hash represents entire document
- Tamper detection at chunk level

---

## Integration Architecture

### LangChain Integration

```
LangChain Agent
       |
       v
TrustChainLangChainTool
       |
       +-- Wraps original function
       +-- Adds signature to response
       +-- Compatible with LangChain protocols
```

### MCP Integration

```
Claude Desktop
       |
       v
MCP Protocol
       |
       v
TrustChain MCP Server
       |
       +-- Exposes tools via JSON-RPC
       +-- Signs all responses
       +-- Stdio transport
```

### CloudEvents Integration

```
Signed Response
       |
       v
TrustEvent
       |
       +-- CloudEvents 1.0 format
       +-- Kafka-compatible headers
       +-- Signature in extension fields
```

---

## Multi-Tenancy

Isolates keys and nonces for multiple customers.

```
TenantManager
       |
       +-- Tenant: acme_corp
       |       +-- TrustChain instance
       |       +-- Unique Ed25519 keypair
       |       +-- Isolated nonce storage
       |
       +-- Tenant: beta_inc
               +-- TrustChain instance
               +-- Unique Ed25519 keypair
               +-- Isolated nonce storage
```

---

## Security Model

### Cryptographic Guarantees

| Property | Mechanism |
|----------|-----------|
| Authenticity | Ed25519 signatures |
| Integrity | Signature covers all fields |
| Non-repudiation | Private key required to sign |
| Replay Protection | Unique nonces |
| Ordering | Chain of Trust (parent signatures) |

### Key Management

- Keys generated at TrustChain initialization
- Private key never exposed via API
- Public key available for external verification
- Persistent storage optional (file system or database)

---

## Performance

Benchmarks on Apple M1:

| Metric | Value |
|--------|-------|
| Sign latency | 0.11 ms |
| Verify latency | 0.22 ms |
| Throughput | 9,102 ops/sec |
| Storage overhead | 124 bytes/response |

---

## Deployment Patterns

### Single Instance

```
[Application] --> [TrustChain] --> [Memory NonceStorage]
```

Best for: Development, small deployments

### Distributed

```
[App Instance 1] --> [TrustChain] --> [Redis]
[App Instance 2] --> [TrustChain] ----^
[App Instance 3] --> [TrustChain] ----^
```

Best for: Production, horizontal scaling

### Multi-Tenant SaaS

```
[Request] --> [TenantManager] --> [TrustChain per Tenant]
                                        |
                                  [Redis per Tenant]
```

Best for: SaaS platforms, enterprise
