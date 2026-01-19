# TrustChain v2.1

**Cryptographic verification layer for AI agents - "SSL for AI"**

[![CI](https://github.com/petro1eum/trust_chain/actions/workflows/ci.yml/badge.svg)](https://github.com/petro1eum/trust_chain/actions/workflows/ci.yml)
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

TrustChain adds **Ed25519 cryptographic signatures** to AI tool responses, enabling:

- **Proof of execution** - data came from a real tool, not hallucinated
- **Chain of Trust** - cryptographically linked operation sequences
- **Replay attack protection** - nonce-based anti-replay
- **Key rotation** - seamless key management with persistence
- **Audit trails** - beautiful HTML reports for compliance
- **Integrations** - OpenAI, Anthropic, LangChain, MCP (Claude Desktop)

---

## Installation

```bash
pip install trustchain
```

**Optional extras:**

```bash
pip install trustchain[integrations]  # LangChain + MCP support
pip install trustchain[ai]            # OpenAI + Anthropic + LangChain
pip install trustchain[mcp]           # MCP Server only
pip install trustchain[redis]         # Distributed nonce storage
pip install trustchain[all]           # Everything
```

---

## Quick Start

```python
from trustchain import TrustChain

tc = TrustChain()

@tc.tool("weather")
def get_weather(city: str) -> dict:
    return {"city": city, "temp": 22}

# Calling the function returns a SignedResponse
result = get_weather("Moscow")
print(result.data)       # {'city': 'Moscow', 'temp': 22}
print(result.signature)  # Ed25519 signature (Base64)

# Verify authenticity
assert tc.verify(result) == True
```

---

## Features

### Chain of Trust

Link operations cryptographically to prove execution order:

```python
step1 = tc._signer.sign("search", {"query": "balance"})
step2 = tc._signer.sign("analyze", {"result": 100}, parent_signature=step1.signature)
step3 = tc._signer.sign("report", {"text": "Done"}, parent_signature=step2.signature)

# Verify the entire chain
assert tc.verify_chain([step1, step2, step3]) == True
```

### Key Management

```python
from trustchain import TrustChain, TrustChainConfig

# Persistent keys with auto-save
tc = TrustChain(TrustChainConfig(
    key_file="keys.json",
    enable_nonce=True
))
tc.save_keys()

# Key rotation (generates new keys)
old_key = tc.get_key_id()
new_key = tc.rotate_keys()  # Also saves if key_file is configured
print(f"Rotated from {old_key[:16]} to {new_key[:16]}")

# Export for external verification
public_key = tc.export_public_key()
```

### Multi-Tenant (Agent Isolation)

```python
from trustchain.v2.tenants import TenantManager

manager = TenantManager()

research_agent = manager.get_or_create("research_agent")
code_agent = manager.get_or_create("code_agent")

# Each agent has isolated keys - cannot verify each other's signatures
result = research_agent._signer.sign("data", {"value": 42})
assert research_agent.verify(result) == True
assert code_agent.verify(result) == False  # Different keys!
```

### OpenAI / Anthropic Schema Export

```python
# Get OpenAI-compatible function schema
schema = tc.get_tools_schema()

# Anthropic format
schema = tc.get_tools_schema(format="anthropic")
```

### MCP Server (Claude Desktop)

```python
from trustchain.integrations.mcp import serve_mcp

@tc.tool("calculator")
def add(a: int, b: int) -> int:
    return a + b

serve_mcp(tc)  # Starts MCP server for Claude Desktop
```

### LangChain Integration

```python
from trustchain.integrations.langchain import to_langchain_tools

lc_tools = to_langchain_tools(tc)
# Use with LangChain AgentExecutor
```

### Merkle Trees for Large Documents

```python
from trustchain.v2.merkle import MerkleTree, verify_proof

pages = ["Page 1...", "Page 2...", ...]
tree = MerkleTree.from_chunks(pages)

# Verify single page without loading entire document
proof = tree.get_proof(42)
assert verify_proof(pages[42], proof, tree.root)
```

### CloudEvents Format

```python
from trustchain.v2.events import TrustEvent

event = TrustEvent.from_signed_response(result, source="/agent/bot")
kafka_headers = event.to_kafka_headers()
```

### Audit Trail UI

```python
from trustchain.ui.explorer import ChainExplorer

explorer = ChainExplorer(chain, tc)
explorer.export_html("audit_report.html")

# Export formats
json_data = explorer.to_json()  # Returns list of responses
stats = explorer.get_stats()     # Summary statistics
```

---

## Performance

| Operation | Latency | Throughput |
|-----------|---------|------------|
| Sign | 0.11 ms | 9,100 ops/sec |
| Verify | 0.22 ms | 4,500 ops/sec |
| Merkle (100 pages) | 0.18 ms | 5,400 ops/sec |

Storage overhead: ~124 bytes per operation.

---

## Interactive Examples

See the `examples/` directory:

| Notebook | Description |
|----------|-------------|
| [trustchain_tutorial.ipynb](examples/trustchain_tutorial.ipynb) | Basic tutorial - 7 core use cases |
| [trustchain_advanced.ipynb](examples/trustchain_advanced.ipynb) | Advanced - key persistence, multi-agent, Redis |
| [trustchain_pro.ipynb](examples/trustchain_pro.ipynb) | Full API reference with all v2.1 capabilities |

**Python examples:**
- `mcp_claude_desktop.py` - MCP Server for Claude
- `langchain_agent.py` - LangChain integration
- `secure_rag.py` - RAG with Merkle verification
- `database_agent.py` - SQL with Chain of Trust
- `api_agent.py` - HTTP client with CloudEvents

---

## Architecture

```
trustchain/
  v2/
    core.py         # Main TrustChain class
    signer.py       # Ed25519 signatures
    schemas.py      # OpenAI/Anthropic schema generation
    merkle.py       # Merkle tree implementation
    events.py       # CloudEvents format
    tenants.py      # Multi-tenant isolation
    nonce_storage.py # Memory/Redis nonce storage
    server.py       # REST API
  integrations/
    langchain.py    # LangChain adapter
    mcp.py          # MCP Server
  ui/
    explorer.py     # HTML audit reports
```

---

## Use Cases

| Industry | Application |
|----------|-------------|
| **AI Agents** | Prove tool outputs are real, not hallucinations |
| **FinTech** | Audit trail for financial operations |
| **LegalTech** | Document verification with Merkle proofs |
| **Healthcare (HIPAA)** | Compliant AI data handling |
| **Enterprise** | SOC2-ready AI deployments |

---

## Documentation

- [Russian Guide](GUIDE_RU.md) - Comprehensive documentation in Russian
- [Roadmap](ROADMAP.md) - Development roadmap and status
- [Architecture](docs/ARCHITECTURE.md) - Technical details
- [GitHub Wiki](https://github.com/petro1eum/trust_chain/wiki) - Full API reference

---

## License

MIT

## Author

Ed Cherednik

## Version

2.1.0