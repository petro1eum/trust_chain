# Getting Started

This guide will help you get TrustChain up and running in 5 minutes.

## Installation

```bash
pip install trustchain
```

With optional integrations:

```bash
pip install trustchain[integrations]  # LangChain + MCP
pip install trustchain[ai]            # OpenAI + Anthropic + LangChain
```

## Basic Usage

### 1. Create a TrustChain Instance

```python
from trustchain import TrustChain

tc = TrustChain()
```

### 2. Register a Tool

Use the `@tc.tool()` decorator to make any function a signed tool:

```python
@tc.tool("calculator")
def add(a: int, b: int) -> int:
    """Add two numbers."""
    return a + b
```

### 3. Call the Tool

When you call the function, you get a `SignedResponse`:

```python
result = add(2, 3)

print(result.data)       # 5 (the actual result)
print(result.signature)  # Base64-encoded Ed25519 signature
print(result.nonce)      # Unique ID for replay protection
print(result.timestamp)  # Unix timestamp
```

### 4. Verify the Response

```python
is_valid = tc.verify(result)
print(is_valid)  # True
```

## SignedResponse Fields

| Field | Description |
|-------|-------------|
| `data` | The actual function return value |
| `signature` | Ed25519 signature in Base64 |
| `signature_id` | Unique signature identifier |
| `nonce` | UUID for replay protection |
| `timestamp` | Unix timestamp of creation |
| `tool_id` | Identifier of the tool |
| `parent_signature` | Reference to previous operation (Chain of Trust) |

## Configuration

```python
from trustchain import TrustChain, TrustChainConfig

config = TrustChainConfig(
    algorithm="ed25519",
    enable_nonce=True,
    enable_cache=True,
    cache_ttl=3600,
    key_file="keys.json",  # Persistent keys
)

tc = TrustChain(config)
```

## Key Management

```python
# Save keys for later use
tc.save_keys()

# Rotate to new keys
new_key = tc.rotate_keys()

# Export public key for external verification
public_key = tc.export_public_key()
```

## Portable Receipts

Use `.tcreceipt` when a signed fact must leave your process and be verified by
another team, customer, auditor, or browser.

```python
from trustchain import build_receipt

signed = tc.sign("calculator", {"result": 5})
receipt = build_receipt(
    signed,
    tc.export_public_key(),
    key_id=tc.get_key_id(),
)
receipt.save("calculator_result.tcreceipt")

assert receipt.verify(expected_public_key_b64=tc.export_public_key()).valid
```

CLI:

```bash
tc receipt show calculator_result.tcreceipt
tc receipt verify calculator_result.tcreceipt --pin BASE64_PUBLIC_KEY
```

## Standards Export

The native `.tcreceipt` remains the source of truth. Export it for standards
ecosystems when needed:

```bash
tc standards export calculator_result.tcreceipt --format scitt -o result.air.json
tc standards export calculator_result.tcreceipt --format w3c-vc -o result.vc.json
tc standards export calculator_result.tcreceipt --format intoto -o result.intoto.json
```

## Chain Anchoring

Store a chain-head checkpoint outside `.trustchain/` so later rewrites are
detectable:

```bash
tc anchor export -d .trustchain -o chain.anchor.json
tc anchor verify chain.anchor.json -d .trustchain
```

## Next Steps

- [API Reference](API-Reference) - Full API documentation
- [Examples](Examples) - Ready-to-use code examples
- [Architecture](Architecture) - Technical deep dive
- [Receipt Spec](../RECEIPTS.md) - `.tcreceipt` format
- [Standards & Positioning](../STANDARDS.md) - SCITT / W3C VC / in-toto
- [Tool PKI](../TOOL_PKI.md) - Tool certificates and code hash integrity
- [Compliance Evidence](../COMPLIANCE.md) - audit/compliance evidence kit
