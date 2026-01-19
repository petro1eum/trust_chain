# TrustChain

**Cryptographic verification layer for AI agents**

TrustChain adds cryptographic signatures to AI tool responses, enabling:
- Proof that data came from a real tool execution (not hallucinated)
- Complete audit trails with Chain of Trust
- Replay attack protection
- Integration with OpenAI, Anthropic, LangChain, and MCP

---

## Installation

```bash
pip install trustchain
```

With optional integrations:
```bash
pip install trustchain[mcp]        # MCP Server support
pip install trustchain[langchain]  # LangChain integration
pip install trustchain[redis]      # Distributed nonce storage
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

## Architecture

```
trustchain/
  v2/
    core.py         # Main TrustChain class
    signer.py       # Ed25519 signatures
    schemas.py      # OpenAI/Anthropic schema generation
    merkle.py       # Merkle tree implementation
    events.py       # CloudEvents format
    server.py       # REST API
  integrations/
    langchain.py    # LangChain adapter
    mcp.py          # MCP Server
  ui/
    explorer.py     # HTML audit reports
```

---

## Examples

See `examples/` directory:
- `mcp_claude_desktop.py` - MCP Server for Claude
- `langchain_agent.py` - LangChain integration
- `secure_rag.py` - RAG with Merkle verification
- `database_agent.py` - SQL with Chain of Trust
- `api_agent.py` - HTTP client with CloudEvents

---

## Use Cases

- **AI Agents**: Prove tool outputs are real, not hallucinations
- **FinTech**: Audit trail for financial operations
- **LegalTech**: Document verification with Merkle proofs
- **Healthcare (HIPAA)**: Compliant AI data handling
- **Enterprise**: SOC2-ready AI deployments

---

## Documentation

- [Russian Guide](GUIDE_RU.md) - Comprehensive documentation in Russian
- [Roadmap](ROADMAP.md) - Development roadmap and status
- [Architecture](docs/ARCHITECTURE.md) - Technical details

---

## License

MIT

## Author

Ed Cherednik

## Version

2.1.0