# LangChain Quickstart: Verify Your Agent in 3 Lines

> **TL;DR**: `pip install trustchain`, decorate your tools with `@tc.tool()`, 
> and every tool response is cryptographically signed. Zero config.

## The Problem

When an LLM says *"The stock price is $185.50"*, how do you know it's real?

Without verification, there's no way to distinguish:
- ✅ Data from an actual API call
- ❌ A hallucinated number that looks plausible

## The Solution: 3 Lines

```python
from trustchain import TrustChain

tc = TrustChain()

@tc.tool("get_stock_price")
def get_stock_price(symbol: str) -> dict:
    """Get current stock price from market API."""
    return {"symbol": symbol, "price": 185.50, "currency": "USD"}

# That's it. Every call to get_stock_price now returns a signed result.
result = get_stock_price("AAPL")
print(result.data)       # {"symbol": "AAPL", "price": 185.50, ...}
print(result.signature)  # Ed25519 signature: "a7b3c9f2..."
print(result.verify())   # True — cryptographically verified
```

## With LangChain

```python
from trustchain import TrustChain
from trustchain.integrations.langchain import to_langchain_tools
from langchain_openai import ChatOpenAI
from langchain.agents import create_tool_calling_agent, AgentExecutor
from langchain_core.prompts import ChatPromptTemplate

# 1. Define verified tools
tc = TrustChain()

@tc.tool("search_products")
def search_products(query: str) -> dict:
    """Search product catalog. Every result is Ed25519-signed."""
    return {"products": [...], "total": 42}

@tc.tool("get_price")
def get_price(product_id: str) -> dict:
    """Get product price. Signature proves this came from a real database."""
    return {"product_id": product_id, "price": 45000, "currency": "RUB"}

# 2. Convert to LangChain tools — one line
lc_tools = to_langchain_tools(tc)

# 3. Use normally — all responses are now signed
llm = ChatOpenAI(model="gpt-4")
prompt = ChatPromptTemplate.from_messages([
    ("system", "You are a helpful assistant. Use tools when needed."),
    ("human", "{input}"),
    ("placeholder", "{agent_scratchpad}"),
])
agent = create_tool_calling_agent(llm, lc_tools, prompt)
executor = AgentExecutor(agent=agent, tools=lc_tools)

result = executor.invoke({"input": "What's the price of product P-001?"})
# Every tool call in this chain is cryptographically signed ✅
```

## What Happens Under the Hood

```
User asks → LLM decides to call get_price("P-001")
                    ↓
            TrustChain intercepts
                    ↓
            Executes real function
                    ↓
            Signs result with Ed25519
                    ↓
            Returns: {data, signature, chain_id}
                    ↓
            LLM receives verified data
                    ↓
            Response shows 🛡️ shields on verified facts
```

## FactSeal v2: Know Exactly What's Verified

TrustChain doesn't just sign the whole blob — it creates a **fact manifest** 
listing exactly which data points are cryptographically attested:

```python
@tc.tool("get_invoice", fact_fields=["amount", "due_date", "vendor"])
def get_invoice(invoice_id: str) -> dict:
    return {
        "invoice_id": invoice_id,
        "amount": 450000,
        "due_date": "2026-05-15",
        "vendor": "ООО Технопром",
    }
```

The response includes `__fact_manifest__`:
```json
{
  "__fact_manifest__": [
    {"path": "amount", "value": "450000", "critical": true, "label": "Amount"},
    {"path": "due_date", "value": "2026-05-15", "critical": true, "label": "Due Date"},
    {"path": "vendor", "value": "ООО Технопром", "label": "Vendor"}
  ]
}
```

If the LLM **omits or distorts** a `critical: true` fact, the UI alerts the user.

## Verify Offline

No server needed. Download the agent's X.509 certificate and verify locally:

```python
import httpx
from cryptography.x509 import load_pem_x509_certificate

cert = load_pem_x509_certificate(
    httpx.get("https://keys.trust-chain.ai/api/pub/agents/my-agent/cert").content
)
cert.public_key().verify(signature_bytes, data_bytes)
```

## Comparison: With vs Without TrustChain

| | Without TrustChain | With TrustChain |
|---|---|---|
| Tool results | Plain JSON | JSON + Ed25519 signature |
| Data provenance | "Trust the LLM" | Cryptographic proof |
| Hallucination detection | Hope for the best | Missing fact alerts |
| Audit trail | None | Merkle tree log |
| Client verification | Not possible | Offline + online |
| Compliance (EU AI Act) | Manual docs | Automatic logging |

## Links

- **PyPI**: [trustchain](https://pypi.org/project/trustchain/)
- **GitHub**: [petro1eum/trust_chain](https://github.com/petro1eum/trust_chain)
- **Public Registry**: [keys.trust-chain.ai](https://keys.trust-chain.ai)
- **Embeddable Badge**: [badge.js docs](https://keys.trust-chain.ai/badge.js)
