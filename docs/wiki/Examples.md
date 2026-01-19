# Examples

Ready-to-use code examples for common TrustChain use cases.

## 1. Basic Tool Signing

The simplest use case: sign any function's output.

```python
from trustchain import TrustChain

tc = TrustChain()

@tc.tool("weather")
def get_weather(city: str) -> dict:
    """Get weather for a city."""
    return {"city": city, "temp": 22, "unit": "celsius"}

# Call the tool
result = get_weather("London")

# Access the data
print(result.data)  # {"city": "London", "temp": 22, "unit": "celsius"}

# Verify the signature
assert tc.verify(result)
```

---

## 2. Chain of Trust

Link multiple operations to prove execution order.

```python
from trustchain import TrustChain

tc = TrustChain()

# Step 1: Search
step1 = tc._signer.sign("search", {"query": "AI security"})

# Step 2: Analyze (linked to step 1)
step2 = tc._signer.sign(
    "analyze", 
    {"results": 42},
    parent_signature=step1.signature
)

# Step 3: Report (linked to step 2)
step3 = tc._signer.sign(
    "report",
    {"summary": "Analysis complete"},
    parent_signature=step2.signature
)

# Verify the entire chain
chain = [step1, step2, step3]
assert tc.verify_chain(chain)
```

---

## 3. Database Agent

Secure database operations with audit trails.

```python
from trustchain import TrustChain

tc = TrustChain()

@tc.tool("db_query")
def query_users(department: str) -> list:
    """Query users by department."""
    # Your database logic here
    return [
        {"id": 1, "name": "Alice", "role": "Engineer"},
        {"id": 2, "name": "Bob", "role": "Manager"},
    ]

@tc.tool("db_update")
def update_user(user_id: int, data: dict) -> dict:
    """Update user information."""
    # Your update logic here
    return {"updated": True, "user_id": user_id}

# All operations are signed
users = query_users("Engineering")
update = update_user(1, {"role": "Senior Engineer"})

# Full audit trail
print(f"Query signature: {users.signature}")
print(f"Update signature: {update.signature}")
```

---

## 4. Secure RAG with Merkle Trees

Verify large documents efficiently.

```python
from trustchain import TrustChain
from trustchain.v2.merkle import MerkleTree, verify_proof

tc = TrustChain()

# Split document into chunks
document_chunks = [
    "Chapter 1: Introduction to AI Security...",
    "Chapter 2: Cryptographic Fundamentals...",
    "Chapter 3: Implementation Patterns...",
]

# Build Merkle tree
tree = MerkleTree.from_chunks(document_chunks)

@tc.tool("rag_search")
def search_document(query: str) -> dict:
    """Search document and return verified chunk."""
    # Simulate finding chunk at index 1
    chunk_index = 1
    chunk = document_chunks[chunk_index]
    proof = tree.get_proof(chunk_index)
    
    return {
        "chunk": chunk,
        "proof": {
            "index": chunk_index,
            "path": [h for h in proof.path],
            "root": proof.root,
        }
    }

# Search returns verified chunk
result = search_document("cryptographic")

# Verify chunk belongs to original document
proof = tree.get_proof(1)
assert verify_proof(document_chunks[1], proof, tree.root)
```

---

## 5. LangChain Integration

Use TrustChain tools with LangChain agents.

```python
from trustchain import TrustChain
from trustchain.integrations.langchain import to_langchain_tools
from langchain.agents import initialize_agent
from langchain.llms import OpenAI

tc = TrustChain()

@tc.tool("calculator")
def calculate(expression: str) -> float:
    """Evaluate a math expression."""
    return eval(expression)

@tc.tool("search")
def search(query: str) -> list:
    """Search for information."""
    return [{"title": "Result 1"}, {"title": "Result 2"}]

# Convert to LangChain tools
lc_tools = to_langchain_tools(tc)

# Use with LangChain agent
llm = OpenAI()
agent = initialize_agent(lc_tools, llm, agent="zero-shot-react-description")
```

---

## 6. MCP Server for Claude Desktop

Expose tools to Claude Desktop via MCP.

```python
from trustchain import TrustChain
from trustchain.integrations.mcp import serve_mcp

tc = TrustChain()

@tc.tool("file_read")
def read_file(path: str) -> str:
    """Read file contents."""
    with open(path) as f:
        return f.read()

@tc.tool("file_write")
def write_file(path: str, content: str) -> dict:
    """Write content to file."""
    with open(path, 'w') as f:
        f.write(content)
    return {"written": len(content)}

# Start MCP server
if __name__ == "__main__":
    serve_mcp(tc)
```

Configure in Claude Desktop's `mcp_servers.json`:

```json
{
  "trustchain": {
    "command": "python",
    "args": ["/path/to/your/script.py"]
  }
}
```

---

## 7. CloudEvents for Kafka

Stream signed events to Kafka.

```python
from trustchain import TrustChain
from trustchain.v2.events import TrustEvent
from kafka import KafkaProducer

tc = TrustChain()

@tc.tool("payment")
def process_payment(amount: float, currency: str) -> dict:
    """Process a payment."""
    return {"status": "completed", "amount": amount, "currency": currency}

# Process payment
result = process_payment(100.0, "USD")

# Create CloudEvent
event = TrustEvent.from_signed_response(
    result,
    source="/payments/processor"
)

# Send to Kafka
producer = KafkaProducer(bootstrap_servers="localhost:9092")
producer.send(
    "payments",
    value=event.to_json().encode(),
    headers=list(event.to_kafka_headers().items())
)
```

---

## 8. Multi-Tenant SaaS

Isolated keys for each customer.

```python
from trustchain.v2.tenants import TenantManager

manager = TenantManager(
    key_storage_dir="./tenant_keys",
    redis_url="redis://localhost:6379"
)

# Get or create tenant instances
tc_acme = manager.get_or_create("acme_corp")
tc_beta = manager.get_or_create("beta_inc")

# Each tenant has isolated keys
@tc_acme.tool("acme_data")
def get_acme_data():
    return {"tenant": "acme", "data": [1, 2, 3]}

@tc_beta.tool("beta_data")
def get_beta_data():
    return {"tenant": "beta", "data": [4, 5, 6]}

# Signatures use different keys
acme_result = get_acme_data()
beta_result = get_beta_data()

# Cross-tenant verification fails
assert tc_acme.verify(acme_result)  # True
# tc_acme.verify(beta_result) would fail
```

---

## 9. Audit Trail HTML Export

Generate visual audit reports.

```python
from trustchain import TrustChain
from trustchain.ui.explorer import AuditExplorer

tc = TrustChain()

@tc.tool("action1")
def action_one():
    return "Step 1 complete"

@tc.tool("action2")
def action_two():
    return "Step 2 complete"

# Collect responses
responses = [action_one(), action_two()]

# Generate HTML report
explorer = AuditExplorer()
html = explorer.generate(responses, tc)

with open("audit_report.html", "w") as f:
    f.write(html)
```

---

## Running Examples

All examples are available in the `examples/` directory:

```bash
# Clone the repository
git clone https://github.com/petro1eum/trust_chain.git
cd trust_chain

# Install with all dependencies
pip install -e ".[integrations]"

# Run an example
python examples/database_agent.py
```

---

## 10. Key Rotation

Rotate keys for security or compliance.

```python
from trustchain import TrustChain, TrustChainConfig

config = TrustChainConfig(key_file="keys.json")
tc = TrustChain(config)
tc.save_keys()

# Current key
old_key = tc.get_key_id()
print(f"Current key: {old_key[:16]}...")

# Rotate to new keys
new_key = tc.rotate_keys()
print(f"New key: {new_key[:16]}...")

# Export public key for external verification
public_key = tc.export_public_key()
```

---

## Interactive Jupyter Notebooks

| Notebook | Description |
|----------|-------------|
| [trustchain_tutorial.ipynb](../examples/trustchain_tutorial.ipynb) | Basic tutorial - 7 core use cases |
| [trustchain_advanced.ipynb](../examples/trustchain_advanced.ipynb) | Advanced - key persistence, multi-agent, Redis |
| [trustchain_pro.ipynb](../examples/trustchain_pro.ipynb) | Full API reference with all v2.1 capabilities |

