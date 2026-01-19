# FAQ

Frequently asked questions about TrustChain.

---

## General

### What problem does TrustChain solve?

TrustChain addresses the trust gap in AI agent systems. When an AI agent calls external tools (APIs, databases, file systems), there's no cryptographic proof that:
- The tool actually executed
- The response wasn't tampered with
- The operations happened in the claimed order

TrustChain adds Ed25519 signatures to every tool response, creating verifiable proof of execution.

### Is TrustChain a blockchain?

No. TrustChain uses cryptographic signatures similar to blockchain technology, but without the distributed consensus mechanism. It's designed for:
- Single-organization deployments
- Low latency (sub-millisecond signing)
- Simple integration (no network overhead)

Think of it as "SSL for AI agents" rather than a blockchain.

### What signature algorithm is used?

Ed25519, a modern elliptic curve signature algorithm. It provides:
- 128-bit security level
- Fast signing and verification
- Small signatures (64 bytes)
- Deterministic signatures (same input = same output)

---

## Integration

### How do I integrate with LangChain?

```python
from trustchain import TrustChain
from trustchain.integrations.langchain import to_langchain_tools

tc = TrustChain()

@tc.tool("my_tool")
def my_function(x: int) -> int:
    return x * 2

lc_tools = to_langchain_tools(tc)
# Use lc_tools with LangChain agents
```

### How do I use TrustChain with Claude Desktop?

1. Create an MCP server script:

```python
from trustchain import TrustChain
from trustchain.integrations.mcp import serve_mcp

tc = TrustChain()

@tc.tool("example")
def example_tool():
    return "Hello from TrustChain"

serve_mcp(tc)
```

2. Configure Claude Desktop's `mcp_servers.json`:

```json
{
  "trustchain": {
    "command": "python",
    "args": ["/path/to/your/script.py"]
  }
}
```

### Does TrustChain work with async functions?

Yes. Use the same `@tc.tool()` decorator:

```python
@tc.tool("async_tool")
async def fetch_data(url: str) -> dict:
    async with aiohttp.ClientSession() as session:
        async with session.get(url) as response:
            return await response.json()
```

---

## Security

### How does replay protection work?

Each `SignedResponse` includes a unique nonce (UUID). When verifying:
1. TrustChain checks if the nonce was used before
2. If used, raises `NonceReplayError`
3. If not used, marks it as used and proceeds

This prevents attackers from replaying old responses.

### Can I verify signatures externally?

Yes. Export the public key and use any Ed25519 library:

```python
from trustchain import TrustChain

tc = TrustChain()
public_key = tc.get_key_id()  # Base64-encoded public key

# Share public_key with external verifiers
```

### What happens if the private key is compromised?

1. Generate a new TrustChain instance (new keypair)
2. Rotate the public key in all verifiers
3. Previous signatures remain valid but should not be trusted

We recommend key rotation policies for production deployments.

---

## Performance

### What is the performance overhead?

Minimal:
- Sign: ~0.11 ms per operation
- Verify: ~0.22 ms per operation
- Storage: ~124 bytes per response

For most applications, this overhead is negligible.

### Can TrustChain handle high throughput?

Yes. Benchmarks show ~9,000 operations per second on a single core. For higher throughput:
- Use Redis backend for distributed nonce storage
- Deploy multiple application instances

### Does Redis add latency?

Yes, but minimal (~1-2 ms per operation). The tradeoff is:
- Memory backend: Fastest, but single-instance only
- Redis backend: Slightly slower, but distributed

---

## Chain of Trust

### What is Chain of Trust?

Chain of Trust links operations cryptographically. Each response includes the previous response's signature as `parent_signature`. This proves:
- Operations happened in a specific order
- No operations were inserted or removed
- The chain wasn't tampered with

### How do I build a chain?

```python
step1 = tc._signer.sign("tool1", data1)
step2 = tc._signer.sign("tool2", data2, parent_signature=step1.signature)
step3 = tc._signer.sign("tool3", data3, parent_signature=step2.signature)

tc.verify_chain([step1, step2, step3])
```

### Can chains branch?

Yes. Multiple responses can reference the same parent:

```
step1 --> step2a
     \--> step2b
```

This is useful for parallel operations that share a common predecessor.

---

## Merkle Trees

### When should I use Merkle Trees?

Use Merkle Trees when:
- Documents are large (many KB or MB)
- You need to verify individual chunks
- Storage or bandwidth is limited

They're ideal for RAG systems where you return document fragments.

### How do I verify a chunk?

```python
from trustchain.v2.merkle import MerkleTree, verify_proof

chunks = ["chunk1", "chunk2", "chunk3"]
tree = MerkleTree.from_chunks(chunks)

proof = tree.get_proof(1)  # Proof for chunk at index 1
is_valid = verify_proof(chunks[1], proof, tree.root)
```

---

## Troubleshooting

### NonceReplayError when running tests

This happens when the same nonce is used twice. Solutions:
1. Create a fresh `TrustChain` instance for each test
2. Call `tc._nonce_storage.clear()` between tests

### Signature verification fails

Check:
1. Data wasn't modified after signing
2. Correct TrustChain instance is used for verification
3. For multi-tenant, use the correct tenant's instance

### ModuleNotFoundError for integrations

Install the required extras:

```bash
pip install trustchain[langchain]  # For LangChain
pip install trustchain[mcp]        # For MCP
pip install trustchain[redis]      # For Redis backend
```

---

## Production

### How should I deploy in production?

Recommended setup:
1. Use Redis backend for nonce storage
2. Store keys persistently (file system or vault)
3. Enable metrics for monitoring
4. Rotate keys periodically

```python
from trustchain import TrustChain, TrustChainConfig

config = TrustChainConfig(
    storage_backend="redis",
    redis_url="redis://localhost:6379",
    enable_metrics=True,
)

tc = TrustChain(config)
```

### Is TrustChain SOC2 compliant?

TrustChain provides the cryptographic foundation for SOC2 compliance:
- Audit trails with tamper detection
- Non-repudiation of operations
- Chain of custody for data

However, SOC2 compliance depends on your overall infrastructure, not just TrustChain.

---

## Contributing

### How can I contribute?

1. Fork the repository: https://github.com/petro1eum/trust_chain
2. Create a feature branch
3. Write tests for your changes
4. Submit a pull request

### Where do I report bugs?

Open an issue on GitHub: https://github.com/petro1eum/trust_chain/issues
