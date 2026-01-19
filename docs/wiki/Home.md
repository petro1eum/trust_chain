# TrustChain

TrustChain is a cryptographic verification layer for AI agent tool calls. It adds Ed25519 signatures to every tool response, enabling proof of authenticity, tamper detection, and complete audit trails.

## Key Features

- **Cryptographic Signatures**: Every tool response is signed with Ed25519
- **Replay Protection**: Nonce-based protection against replay attacks
- **Chain of Trust**: Link operations cryptographically to prove execution order
- **Key Rotation**: Seamless key management with persistence
- **Merkle Trees**: Verify large documents with compact proofs
- **CloudEvents**: Standard event format for Kafka and other systems

## Use Cases

| Industry | Use Case |
|----------|----------|
| FinTech | Audit trails for AI-driven financial operations |
| LegalTech | Document verification with Merkle proofs |
| Healthcare | HIPAA-compliant AI data handling |
| Enterprise | SOC2-ready AI deployments |

## Quick Links

- [Getting Started](Getting-Started)
- [API Reference](API-Reference)
- [Examples](Examples)
- [Architecture](Architecture)
- [FAQ](FAQ)

## Installation

```bash
pip install trustchain
```

With optional integrations:

```bash
pip install trustchain[integrations]  # LangChain + MCP
pip install trustchain[ai]            # OpenAI + Anthropic + LangChain
pip install trustchain[mcp]           # MCP Server only
pip install trustchain[redis]         # Distributed nonce storage
```

## Basic Example

```python
from trustchain import TrustChain

tc = TrustChain()

@tc.tool("weather")
def get_weather(city: str) -> dict:
    return {"city": city, "temp": 22}

result = get_weather("London")
print(result.signature)  # Ed25519 signature
print(tc.verify(result)) # True
```

## Interactive Examples

| Notebook | Description |
|----------|-------------|
| [trustchain_tutorial.ipynb](../examples/trustchain_tutorial.ipynb) | Basic tutorial - 7 core use cases |
| [trustchain_advanced.ipynb](../examples/trustchain_advanced.ipynb) | Advanced - key persistence, multi-agent |
| [trustchain_pro.ipynb](../examples/trustchain_pro.ipynb) | Full API reference |

## Version

Current version: 2.1.0

## License

MIT License
