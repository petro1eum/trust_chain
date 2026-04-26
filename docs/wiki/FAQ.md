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

For portable evidence, TrustChain can wrap a signed response into a `.tcreceipt`
file that another team, customer, auditor, or browser can verify offline.

### Is TrustChain a blockchain?

No. TrustChain uses cryptographic signatures similar to blockchain technology, but without the distributed consensus mechanism. It's designed for:
- Single-organization deployments
- Low latency (sub-millisecond signing)
- Simple integration (no network overhead)

Think of it as "SSL for AI agents" rather than a blockchain.

For stronger evidence, you can export a chain-head checkpoint with
`tc anchor export` and store it outside the local `.trustchain/` directory.

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

---

## Receipts, Standards, and Anchoring

### What is a `.tcreceipt`?

A `.tcreceipt` is a portable JSON proof containing:

- the signed TrustChain envelope;
- the public key and key id;
- optional identity/certificate material;
- optional witness evidence;
- a human-readable summary.

It lets a verifier check the signature without contacting the original agent.

### How do I create and verify a receipt?

```bash
tc receipt build signed_response.json --key pubkey.json -o result.tcreceipt
tc receipt show result.tcreceipt
tc receipt verify result.tcreceipt --pin BASE64_PUBLIC_KEY
```

Python:

```python
from trustchain import build_receipt

signed = tc.sign("tool", {"answer": 42})
receipt = build_receipt(signed, tc.export_public_key(), key_id=tc.get_key_id())
assert receipt.verify(expected_public_key_b64=tc.export_public_key()).valid
```

### Does TrustChain support SCITT, W3C VC, or in-toto?

Yes, through export adapters. The native `.tcreceipt` remains the source of
truth; standards exports are wrappers for interoperability.

```bash
tc standards export result.tcreceipt --format scitt
tc standards export result.tcreceipt --format w3c-vc
tc standards export result.tcreceipt --format intoto
```

Python:

```python
from trustchain.standards import to_scitt_air_json, to_w3c_vc, to_intoto_statement
```

### What does anchoring do?

Anchoring exports the current chain HEAD and canonical chain digest:

```bash
tc anchor export -d .trustchain -o chain.anchor.json
tc anchor verify chain.anchor.json -d .trustchain
```

If you store `chain.anchor.json` outside the agent's writable environment, later
rewrites of the whole local chain become detectable.

### What is Tool PKI?

Tool PKI certifies tool implementations. A `ToolCertificate` contains the tool
name, module, version, permissions, issuer, and source-code hash. At runtime,
`ToolRegistry.verify()` recomputes the hash and rejects the tool if the code no
longer matches, the certificate expired, or it was revoked.

```python
from trustchain.v2.certificate import ToolRegistry

registry = ToolRegistry()
registry.certify(my_tool, owner="Risk Engineering")
assert registry.verify(my_tool)
```

This is different from a normal action receipt: it proves not only that some key
signed output, but also that the expected tool implementation produced it.

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
