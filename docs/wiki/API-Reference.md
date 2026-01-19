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
