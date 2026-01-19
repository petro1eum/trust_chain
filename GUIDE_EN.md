# TrustChain -- User Guide

## What is TrustChain?

TrustChain is a Python library for cryptographic signing of AI tool responses. It solves the trust problem: when an AI agent calls a function (tool), there's no guarantee that the result is real and not a hallucination.

TrustChain adds to every response:
- Cryptographic signature (Ed25519)
- Unique nonce (replay attack protection)
- Timestamp
- Optionally: link to previous step (Chain of Trust)

---

## Requirements

- **Python 3.10+** (3.13 recommended)
- Package manager: `uv` (recommended) or `pip`

---

## Installation

We recommend using **uv** for fast installation:

```bash
uv pip install trustchain
```

Or standard pip:

```bash
pip install trustchain
```

For additional features:

```bash
uv pip install trustchain[integrations]  # LangChain + MCP
uv pip install trustchain[ai]            # OpenAI + Anthropic + LangChain
uv pip install trustchain[mcp]           # MCP Server only
uv pip install trustchain[redis]         # Distributed nonce storage
uv pip install trustchain[all]           # Everything
```

---

## Quick Start

### Basic Usage

```python
from trustchain import TrustChain

# Create TrustChain instance
tc = TrustChain()

# Register function as a signed tool
@tc.tool("weather")
def get_weather(city: str) -> dict:
    """Get weather for a city."""
    return {"city": city, "temp": 22, "conditions": "sunny"}

# Call function -- get signed response
result = get_weather("Moscow")

# result is a SignedResponse object
print(result.data)       # {'city': 'Moscow', 'temp': 22, ...}
print(result.signature)  # Base64-encoded Ed25519 signature
print(result.nonce)      # UUID for replay protection
```

### Signature Verification

```python
# Verify response authenticity
is_valid = tc.verify(result)
print(is_valid)  # True

# Repeated verification of same nonce -- error
try:
    tc.verify(result)
except NonceReplayError:
    print("Replay attack detected!")
```

---

## Core Concepts

### SignedResponse

When you call a function wrapped with `@tc.tool()` decorator, it returns not raw data but a `SignedResponse` object:

| Field | Description |
|-------|-------------|
| `data` | Function result (any type) |
| `signature` | Ed25519 signature in Base64 |
| `signature_id` | Unique signature ID (UUID) |
| `timestamp` | Unix timestamp of creation |
| `nonce` | Unique ID for replay protection |
| `tool_id` | Tool identifier |
| `parent_signature` | Link to previous step (Chain of Trust) |

### How Signing Works

1. Canonical data representation is created (JSON)
2. Data is hashed with SHA-256
3. Hash is signed with Ed25519 private key
4. Signature is encoded in Base64

Verification:
1. Canonical representation is restored
2. Signature is decoded from Base64
3. Public key verifies the signature

### Replay Attack Protection

Nonce (Number used ONCE) guarantees that each response can only be verified once.

Attack scenario:
```
1. Hacker intercepts response "Transfer $100"
2. Hacker sends it 100 times
3. $10,000 stolen
```

With TrustChain:
```python
tc.verify(result)  # OK -- first time
tc.verify(result)  # NonceReplayError -- nonce already used
```

---

## Chain of Trust

Allows cryptographically linking multiple operations.

### Why is this needed?

When AI performs a multi-step task:
1. Data search
2. Analysis
3. Report generation

You need to prove that step 2 was performed based on step 1, not fabricated.

### Usage

```python
from trustchain import TrustChain

tc = TrustChain()

# Step 1: Search (no parent)
step1 = tc._signer.sign("search", {"query": "balance", "results": [100, 200]})

# Step 2: Analysis (references step 1)
step2 = tc._signer.sign(
    "analyze", 
    {"summary": "total=300"},
    parent_signature=step1.signature  # Link to previous step
)

# Step 3: Report (references step 2)
step3 = tc._signer.sign(
    "report",
    {"text": "Balance is 300"},
    parent_signature=step2.signature
)

# Verify entire chain
chain = [step1, step2, step3]
is_valid = tc.verify_chain(chain)
print(is_valid)  # True -- chain is intact
```

### What does verify_chain check?

1. Each signature is valid
2. Each `parent_signature` matches the `signature` of the previous step
3. Chain is not broken

---

## Configuration

### Basic Options

```python
from trustchain import TrustChain, TrustChainConfig

config = TrustChainConfig(
    algorithm="ed25519",      # Signing algorithm
    enable_nonce=True,        # Replay attack protection
    enable_cache=True,        # Response caching
    cache_ttl=3600,           # Cache lifetime (seconds)
    nonce_ttl=86400,          # Nonce lifetime (seconds)
    key_file="keys.json",     # Key storage file
)

tc = TrustChain(config)
```

### Key Rotation

```python
# Generate new keys
old_key = tc.get_key_id()
new_key = tc.rotate_keys()  # Auto-saves if key_file is configured

print(f"Rotation: {old_key[:16]} -> {new_key[:16]}")

# Export public key for external verification
public_key = tc.export_public_key()
```

> After rotation, all previous signatures become invalid!

### Distributed Configuration (Redis)

For multiple servers:

```python
config = TrustChainConfig(
    nonce_backend="redis",
    redis_url="redis://localhost:6379/0",
    nonce_ttl=86400,
)

tc = TrustChain(config)
```

### Multi-Tenancy

For SaaS with different clients:

```python
from trustchain import TenantManager

manager = TenantManager(
    redis_url="redis://localhost:6379",
    key_storage_dir="./keys"  # Where to store client keys
)

# Get TrustChain for specific client
tc_acme = manager.get_or_create("acme_corp")
tc_beta = manager.get_or_create("beta_inc")

# Each client has their own keys
print(tc_acme.get_key_id())  # key-abc123...
print(tc_beta.get_key_id())  # key-xyz789...
```

---

## Integrations

### OpenAI / Anthropic Schema

TrustChain automatically generates JSON Schema for functions:

```python
# OpenAI format
schema = tc.get_tool_schema("weather")

# Anthropic format
schema = tc.get_tool_schema("weather", format="anthropic")

# All tools at once
all_schemas = tc.get_tools_schema()
```

### LangChain

```python
from trustchain.integrations.langchain import to_langchain_tools

# Convert all TrustChain tools to LangChain format
lc_tools = to_langchain_tools(tc)

# Use with agent
from langchain.agents import AgentExecutor
executor = AgentExecutor(agent=agent, tools=lc_tools)
```

### MCP Server (Claude Desktop)

```python
from trustchain.integrations.mcp import serve_mcp

@tc.tool("calculator")
def add(a: int, b: int) -> int:
    return a + b

# Start MCP server
serve_mcp(tc)
```

For Claude Desktop add to `claude_desktop_config.json`:
```json
{
  "mcpServers": {
    "trustchain": {
      "command": "python",
      "args": ["/path/to/your/mcp_server.py"]
    }
  }
}
```

---

## Performance

Benchmark results (Apple M1):

| Operation | Latency | Throughput |
|-----------|---------|------------|
| Sign | 0.11 ms | 9,102 ops/sec |
| Verify | 0.22 ms | 4,513 ops/sec |
| Chain verify (100 items) | 28 ms | - |
| Merkle (100 pages) | 0.18 ms | 5,482 ops/sec |

Storage overhead: ~124 bytes per operation (88 bytes signature + 36 bytes nonce).

---

## License

MIT

## Author

Ed Cherednik

## Version

2.1.0
