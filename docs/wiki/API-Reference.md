# API Reference

Complete API documentation for TrustChain.

## Core Classes

### TrustChain

The main class for creating and verifying signed tools.

```python
from trustchain import TrustChain

tc = TrustChain(config=None)
```

#### Methods

| Method | Description |
|--------|-------------|
| `tool(tool_id, **options)` | Decorator to create a signed tool |
| `verify(response)` | Verify a signed response |
| `verify_chain(responses)` | Verify a chain of linked responses |
| `get_key_id()` | Get the public key identifier |
| `rotate_keys(save=True)` | Generate new key pair, returns new key ID |
| `export_public_key()` | Export Base64-encoded public key |
| `save_keys(filepath=None)` | Save keys to file |
| `export_keys()` | Export keys as dict for persistence |
| `get_tool_schema(tool_id, format)` | Get OpenAI/Anthropic schema for a tool |
| `get_tools_schema(format)` | Get schemas for all tools |
| `get_stats()` | Get usage statistics |

### Receipt API

Portable `.tcreceipt` files are built from a signed response plus the public key
that verifiers should use.

```python
from trustchain import Receipt, build_receipt, verify_receipt

signed = tc.sign("sec_filing_lookup", {"company": "Acme", "revenue": 42})

receipt = build_receipt(
    signed,
    tc.export_public_key(),
    key_id=tc.get_key_id(),
)
receipt.save("acme_revenue.tcreceipt")

loaded = Receipt.load("acme_revenue.tcreceipt")
result = loaded.verify(expected_public_key_b64=tc.export_public_key())
assert result.valid

same_result = verify_receipt(
    "acme_revenue.tcreceipt",
    expected_public_key_b64=tc.export_public_key(),
)
```

| API | Description |
|-----|-------------|
| `build_receipt(response, public_key_b64, key_id=None)` | Wrap a `SignedResponse` or dict into a `.tcreceipt`. |
| `Receipt.load(path_or_json_or_dict)` | Load a receipt from disk, JSON text, or dict. |
| `Receipt.verify(expected_public_key_b64=None, max_age_seconds=None)` | Verify the native TrustChain signature and optional policy checks. |
| `verify_receipt(source, **kwargs)` | One-shot load + verify helper. |

### Standards API

Standards adapters export TrustChain evidence without replacing the native
receipt format.

```python
from trustchain.standards import (
    to_scitt_air_json,
    to_w3c_vc,
    to_intoto_statement,
)

air = to_scitt_air_json(
    signed,
    agent_id="agent:researcher",
    sequence_number=0,
)

vc = to_w3c_vc(
    receipt,
    issuer="did:web:trust-chain.ai",
    subject_id="did:example:agent",
)

statement = to_intoto_statement(receipt)
```

| API | Output |
|-----|--------|
| `to_scitt_air_json(...)` | SCITT AIR-shaped JSON profile. |
| `verify_scitt_air_json(record)` | Deterministic integrity check for the SCITT JSON profile. |
| `to_w3c_vc(...)` | VC-shaped envelope embedding the native receipt. |
| `verify_w3c_vc_shape(vc)` | Shape/digest consistency check for the VC envelope. |
| `to_intoto_statement(...)` | in-toto Statement v1.0 with TrustChain predicate. |
| `verify_intoto_statement_shape(statement)` | Statement/digest consistency check. |

### Tool PKI API

Tool PKI binds a tool's identity to a source-code hash and certificate metadata.

```python
from trustchain.v2.certificate import ToolRegistry, trustchain_certified

registry = ToolRegistry()

cert = registry.certify(
    my_tool,
    owner="Risk Engineering",
    organization="Acme Bank",
    permissions=["read:customer"],
)

assert registry.verify(my_tool)

@trustchain_certified(registry)
def guarded_tool(customer_id: str) -> dict:
    return my_tool(customer_id)
```

| API | Description |
|-----|-------------|
| `ToolRegistry.certify(func, ...)` | Issue and persist a tool certificate. |
| `ToolRegistry.verify(func)` | Verify certificate presence, expiry/revocation, and code hash. |
| `ToolRegistry.revoke(func, reason)` | Mark a tool certificate as revoked. |
| `compute_code_hash(func)` | Compute the SHA-256 source hash used by certificates. |
| `trustchain_certified(registry)` | Decorator that enforces certificate verification before execution. |

### TrustChainConfig

Configuration options for TrustChain.

```python
from trustchain import TrustChainConfig

config = TrustChainConfig(
    algorithm="ed25519",         # Signature algorithm
    enable_nonce=True,           # Enable replay protection
    enable_cache=True,           # Enable response caching
    cache_ttl=3600,              # Cache TTL in seconds
    nonce_ttl=86400,             # Nonce TTL in seconds
    max_cached_responses=1000,   # Max cached responses
    enable_metrics=False,        # Enable Prometheus metrics
    storage_backend="memory",    # "memory" or "redis"
    redis_url=None,              # Redis URL for distributed mode
    key_file=None,               # Path to save/load keys
)
```

### SignedResponse

Represents a cryptographically signed tool response.

```python
@dataclass
class SignedResponse:
    data: Any                           # Function return value
    signature: str                      # Base64 Ed25519 signature
    signature_id: str                   # Unique ID
    timestamp: float                    # Unix timestamp
    nonce: str                          # Replay protection nonce
    tool_id: str                        # Tool identifier
    parent_signature: Optional[str]     # Chain link
    is_verified: bool                   # Verification status
```

---

## Chain of Trust

### Linking Operations

```python
step1 = tc._signer.sign("search", {"query": "data"})
step2 = tc._signer.sign("analyze", {"result": 100}, parent_signature=step1.signature)
step3 = tc._signer.sign("report", {"text": "Done"}, parent_signature=step2.signature)
```

### Verifying a Chain

```python
chain = [step1, step2, step3]
is_valid = tc.verify_chain(chain)  # True if all links valid
```

---

## Schema Generation

### OpenAI Format

```python
schema = tc.get_tool_schema("weather")
# {
#   "type": "function",
#   "function": {
#     "name": "weather",
#     "description": "Get weather data",
#     "parameters": {...}
#   }
# }
```

### Anthropic Format

```python
schema = tc.get_tool_schema("weather", format="anthropic")
# {
#   "name": "weather",
#   "description": "Get weather data",
#   "input_schema": {...}
# }
```

### All Tools

```python
all_schemas = tc.get_tools_schema()
```

---

## Merkle Trees

For verifying large documents without loading entire content.

### Building a Tree

```python
from trustchain.v2.merkle import MerkleTree, verify_proof

chunks = ["Page 1...", "Page 2...", "Page 3..."]
tree = MerkleTree.from_chunks(chunks)

print(tree.root)  # Single hash for entire document
```

### Getting a Proof

```python
proof = tree.get_proof(1)  # Proof for Page 2
```

### Verifying a Chunk

```python
is_valid = verify_proof(chunks[1], proof, tree.root)
```

---

## CloudEvents

Standard event format for Kafka integration.

```python
from trustchain.v2.events import TrustEvent

event = TrustEvent.from_signed_response(
    response,
    source="/agent/my-bot/tool/weather"
)

# JSON for Kafka
json_str = event.to_json()

# Kafka headers
headers = event.to_kafka_headers()
```

---

## Multi-Tenancy

For SaaS applications with multiple customers.

```python
from trustchain.v2.tenants import TenantManager

manager = TenantManager(
    key_storage_dir="./keys",
    redis_url="redis://localhost:6379"
)

tc_acme = manager.get_or_create("acme_corp")
tc_beta = manager.get_or_create("beta_inc")

# Each tenant has isolated keys
```

---

## Integrations

### LangChain

```python
from trustchain.integrations.langchain import to_langchain_tools

lc_tools = to_langchain_tools(tc)
# Use with LangChain agents
```

### MCP Server

```python
from trustchain.integrations.mcp import serve_mcp

serve_mcp(tc)  # Starts MCP server for Claude Desktop
```

---

## Exceptions

| Exception | Description |
|-----------|-------------|
| `NonceReplayError` | Nonce was already used (replay attack) |
| `SignatureVerificationError` | Signature is invalid |
| `TrustChainError` | Base exception class |
