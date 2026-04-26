# TrustChain Technology Guide

> **SSL for AI-agents.**
> Every fact an AI produces — a tool response, a retrieved document, a reasoning step — can be cryptographically signed, chained, audited, and verified by a third party. Offline. Without trusting the vendor that produced it.
>
> This document explains **what TrustChain does**, **how it is split across tiers**, and **which public APIs you should reach for**. Internal implementation details of Pro/Enterprise features are intentionally omitted.

---

## 1. Why TrustChain exists

Modern LLM agents invent facts, silently mutate tool outputs, and leave almost no verifiable trail. Logs are not evidence — anyone with write access can rewrite them. TrustChain treats AI output the same way browsers treat TLS: you only trust what is signed by a known key, chained to prior state, and verifiable **without calling the agent back**.

TrustChain gives you three guarantees:

| Guarantee | What it means in practice |
|-----------|---------------------------|
| **Authenticity** | This JSON came from tool `X` under key `K` — not from an LLM pretending it did. |
| **Integrity** | The bytes you have now are identical to what was signed. One flipped field invalidates the signature. |
| **Order (chain of trust)** | Step *N* was produced after step *N-1*. You cannot reorder or drop steps without breaking the chain. |

The **OSS** core is MIT-licensed, runs entirely in-process, and has no network dependencies. **Pro** and **Enterprise** layer governance, compliance, and scale on top — as additional PyPI packages and SaaS endpoints — without changing the core trust model.

---

## 2. Core concepts (shared across all tiers)

### 2.1 Signed response

The atomic unit is a `SignedResponse`:

```python
from trustchain import TrustChain, TrustChainConfig

tc = TrustChain(TrustChainConfig(enable_nonce=False))

signed = tc.sign(
    tool_id="weather_api",
    data={"city": "Moscow", "temp_c": 22.5},
)

assert tc.verify(signed)        # True
signed.signature                # base64 Ed25519 signature
signed.public_key_b64           # verifier key
signed.data                     # original payload
signed.response_timestamp       # monotonic UNIX timestamp (signed)
```

The canonical payload is serialized with sorted keys and UTF-8 — the same bytes any verifier can reproduce — and signed with **Ed25519**.

### 2.2 Chain of trust

Every signed response is linked to the current chain HEAD:

```
op_0  -- signs --> H0
op_1  -- signs --> H1 = sig(data_1 || H0)
op_2  -- signs --> H2 = sig(data_2 || H1)
```

If anyone rewrites `op_1`, every later signature breaks. HEAD is persisted by the configured `ChainStore` backend (in-memory, file, or Postgres — see §3.5).

### 2.3 `.tcreceipt` — portable proof (v3)

Sometimes you need to hand a *single fact* to a downstream party (regulator, partner, another agent) without giving them access to your whole chain. TrustChain 3.x introduces the **`.tcreceipt`** format:

```python
from trustchain import TrustChain, TrustChainConfig, build_receipt

tc = TrustChain(TrustChainConfig(enable_nonce=False))
signed = tc.sign("sec_filing_lookup", {"company": "Acme", "revenue_usd": 4_812_300_000})

receipt = build_receipt(
    signed,
    tc.export_public_key(),
    key_id=tc.get_key_id(),
)
open("acme_revenue.tcreceipt", "w").write(receipt.to_json(indent=2))
```

A `.tcreceipt` is one self-contained JSON blob holding:

| Field        | Purpose |
|--------------|---------|
| `envelope`   | Original tool payload + `tool_id` + `response_timestamp`. |
| `signature`  | Ed25519 signature over canonical envelope bytes. |
| `public_key` | Base64 signer key (optionally with `key_id`). |
| `chain`      | Parent signature / HEAD fingerprint (optional). |
| `certificate`| PEM chain when the signer is anchored to a CA (Platform tier). |

Anyone with the file can verify it:

```python
from trustchain import Receipt
r = Receipt.from_json(open("acme_revenue.tcreceipt").read())
result = r.verify(expected_public_key_b64=tc.export_public_key())
assert result.valid
```

The browser can verify the exact same file with **WebCrypto** — there is a reference [`examples/verify.html`](../examples/verify.html) that drag-and-drops a `.tcreceipt` and returns a pass/fail without any network call.

### 2.4 Versioning

| Version | Status | Notes |
|---------|--------|-------|
| **v1**  | legacy | detached signatures, no chain store |
| **v2**  | stable | chained responses, Merkle, tenants, integrations |
| **v3**  | **current** | `.tcreceipt`, DAG merges, compensations, manifest hashing, Postgres-first verifiable log |

`pip install trustchain>=3.0.0` gets you v3. v2 modules remain importable under `trustchain.v2.*` for back-compat.

---

## 3. OSS tier — `pip install trustchain` (MIT)

Everything below ships in the open-source package. No license key, no network call, no phone-home.

### 3.1 `@tc.tool` decorator

Auto-sign any Python callable:

```python
@tc.tool("database_query")
def query(sql: str):
    return db.fetchall(sql)

response = query("SELECT 1")
response.data          # {'rows': [...]}
response.signature     # auto-attached
tc.verify(response)    # True
```

### 3.2 `TrustChain.sign` / `TrustChain.verify`

Low-level API when you don't own the callable (e.g. wrapping a third-party SDK or an LLM tool-call result).

### 3.3 `TrustChainVerifier`

Standalone verifier — no private key, verification only. Useful in consumer services that must trust data coming from another team:

```python
from trustchain import TrustChainVerifier
v = TrustChainVerifier(public_keys=[producer_pubkey_b64])
assert v.verify(signed_response)
```

### 3.4 Async — `AsyncTrustChain`

Drop-in async context manager for FastAPI / asyncio workloads:

```python
from trustchain.v2.async_core import AsyncTrustChain

async with AsyncTrustChain() as atc:
    resp = await atc.sign("embedding_search", {"hits": [...]})
```

### 3.5 Chain storage backends

| Backend | Import | When to use |
|---------|--------|-------------|
| In-memory | default | tests, notebooks |
| File (`.trustchain/`) | set `TC_CHAIN_DIR` | single-node services |
| Postgres verifiable log | `PostgresVerifiableChainStore` | multi-node / production (ADR-SEC-002) |

### 3.6 Merkle verifiable log

`trustchain.v2.merkle.MerkleTree` + `verify_proof` — build and prove inclusion for a batch of signed responses. This is the primitive behind third-party audit trails.

### 3.7 Multi-tenant isolation

`trustchain.v2.tenants.TenantManager` issues isolated `TrustChain` instances per tenant (separate keys, separate chain stores).

### 3.8 Framework integrations

All included in OSS:

| Framework | Module |
|-----------|--------|
| LangChain / LangGraph | `trustchain.integrations.langchain` |
| LangSmith callback | `trustchain.integrations.langsmith` |
| MCP (Model Context Protocol) | `trustchain.integrations.mcp` |
| Pydantic v2 signed models | `trustchain.integrations.pydantic_v2` |
| FastAPI / Starlette middleware | `trustchain.integrations.fastapi` |
| Flask / Django | `trustchain.integrations.flask` / `.django` |
| OpenTelemetry span attributes | `trustchain.integrations.opentelemetry` |
| pytest fixtures | `trustchain.pytest_plugin` |

### 3.9 Standards adapters

TrustChain keeps `.tcreceipt` as the native source of truth, then exports the
same evidence into the standards ecosystems security teams already use:

| Standard surface | Module | Output |
|------------------|--------|--------|
| SCITT / AI Agent Execution | `trustchain.standards.scitt` | AIR-shaped JSON profile with `content_hash`, `prev_chain_hash`, `chain_hash`, `sequence_number`, and `agent_id`. |
| W3C Verifiable Credentials | `trustchain.standards.w3c_vc` | VC-shaped envelope embedding the native `.tcreceipt`. |
| in-toto / Sigstore / DSSE | `trustchain.standards.intoto` | in-toto Statement v1.0 with a TrustChain predicate. |

These adapters are interoperability exports. Full SCITT custody, COSE signing,
transparency admission, retention policy, and enterprise governance remain
deployment-layer concerns.

### 3.10 Tool PKI

Tool PKI binds tool identity to implementation integrity. A `ToolCertificate`
records the tool name, module, version, permissions, issuer, and SHA-256 hash of
the tool source. `ToolRegistry.verify()` recomputes the hash before execution,
so unexpected tool changes are detected before the signed output is trusted.

```python
from trustchain.v2.certificate import ToolRegistry

registry = ToolRegistry()
cert = registry.certify(my_tool, owner="Risk Engineering")
assert registry.verify(my_tool)
```

See [`docs/TOOL_PKI.md`](TOOL_PKI.md) and [`tool-pki.html`](tool-pki.html).

### 3.11 Anchoring

Local hash chains detect edits inside `.trustchain/`, but a powerful attacker
with filesystem access could rewrite the whole directory. OSS anchoring exports
a portable checkpoint that should be stored outside the agent's writable
environment:

```bash
tc anchor export -d .trustchain -o chain.anchor.json
tc anchor verify chain.anchor.json -d .trustchain
```

The anchor contains the current `head`, `length`, canonical `chain_sha256`,
`chain_valid`, and optional `merkle_root`. Pro/Enterprise can schedule this and
submit checkpoints to a transparency service, customer evidence store, TSA, or
object-lock storage.

### 3.12 CLI

```
tc sign <tool_id> <json>           # sign ad-hoc payload
tc verify <file>                   # verify a .tcreceipt / chain entry
tc cert request ...                # request a leaf cert from Platform (optional)
tc-verify file.jsonl.gz            # fully offline batch verify
tc-witness ...                     # external witness co-signer
tc standards export r.tcreceipt --format scitt   # SCITT/W3C VC/in-toto JSON exports
tc anchor export -o chain.anchor.json             # portable chain-head checkpoint
```

### 3.13 v3 primitives

Also OSS:

- `trustchain.v3.objects` — content-addressed objects.
- `trustchain.v3.cas_io` — CAS read/write.
- `trustchain.v3.manifest_hash` — canonical manifest hashing.
- `trustchain.v3.merge_commit` / `log_walk` — DAG merges for agent branches.
- `trustchain.v3.compensations` — reversible action hooks.
- `trustchain.v3.migrate_v2` — migrate an existing v2 chain store.

→ Tutorials: [`examples/trustchain_tutorial.ipynb`](../examples/trustchain_tutorial.ipynb), [`trustchain_receipts.ipynb`](../examples/trustchain_receipts.ipynb), [`trustchain_advanced.ipynb`](../examples/trustchain_advanced.ipynb).

---

## 4. Pro tier — `pip install trustchain-pro`

Pro is a **separate commercial package** that *uses* the OSS core. It adds governance, streaming, compliance exports, and production-grade storage. It is gated by an Ed25519-signed license token (`TRUSTCHAIN_PRO_LICENSE`).

> The sections below describe the **public surface** — the classes and helpers you import. Internal policies, token validation logic, seat management, and license-server schemas are intentionally not covered here.

### 4.1 `PolicyEngine` — YAML governance

Declarative rules evaluated against every signed response or tool call. Blocks, requires approval, rewrites metadata, or routes to a parent operation.

```python
from trustchain_pro import PolicyEngine

engine = PolicyEngine()
engine.load_yaml("""
policies:
  - name: payment_limits
    if:  { tool: payment, "args.amount": { ">": 10000 } }
    then: { action: require, parent_tool: manager_approval }
""")

decision = engine.evaluate(response, args={"amount": 50000})
if not decision.allowed:
    raise PolicyViolation(decision.message)
```

Typical uses: medical-data guardrails, spend limits, regulated-content filters.

### 4.2 `StreamingReasoningChain`

Signs an LLM reasoning stream token-by-token (or step-by-step). Every intermediate step is cryptographically linked to the previous one, so a truncated or re-ordered stream breaks verification.

### 4.3 `RedisHAStorage`

Production nonce storage backed by Redis Sentinel. Plugs into `TrustChainConfig(nonce_storage=...)` for HA replay-attack protection at high QPS.

### 4.4 `ExecutionGraph`

A signed, navigable graph of everything the agent did — tools, sub-agents, tool inputs/outputs, reasoning steps. Renderable to DOT / HTML for auditors.

### 4.5 RFC 3161 timestamping (TSA)

Wrap a signed response with a timestamp token from an RFC 3161-compliant Time-Stamping Authority. Gives you legally-defensible "was alive at time T" evidence.

### 4.6 `FactSeal`

Bundles a fact + its provenance manifest (source URL, retrieval hash, transforms applied) into a single signed object. Designed to be embedded inside `.tcreceipt` files for RAG pipelines.

### 4.7 KMS helpers

Thin helpers around AWS KMS / HashiCorp Vault / Azure Key Vault for key custody. The OSS core supports external KMS via `TrustChainConfig(signer=...)`; Pro ships preconfigured signer factories and rotation policies.

### 4.8 `ComplianceReport`

One call produces an auditor-ready HTML/PDF: signature coverage, policy hits, failures, timestamps, Merkle proofs.

### 4.9 `Analytics`

Aggregated signed-operation metrics (hit rate, failure reasons, tool latency distributions, anomaly scores) exposed as a pluggable data source for Grafana / Superset.

### 4.10 Airgap mode

Offline verification bundle — sealed package of `{public keys, CRL snapshot, TSA certs, policy bundle}` for environments with no internet egress.

→ Docs: [`trust_chain_pro/docs/LICENSING_GUIDE.md`](https://github.com/petro1eum/trust_chain_pro/blob/main/docs/LICENSING_GUIDE.md), license issuance via `tc-license`.

---

## 5. Enterprise tier — `TrustChain_Platform` (SaaS + on-prem)

Enterprise is a **platform deployment**, not a new Python API. It surrounds OSS + Pro with organizational trust:

### 5.1 Root / Intermediate CA and leaf certificates

Every agent, subagent, tool, and skill receives an X.509 leaf certificate chained to the Platform Root CA. `.tcreceipt` files produced inside the platform embed the PEM chain, so a third party can verify both the signature *and* the signer's organization — exactly like TLS for websites.

### 5.2 Public registry

`/api/pub/*` endpoints expose signer metadata, revocation status, and verification keys — so any client (browser, CLI, Chrome extension) can verify a `.tcreceipt` without a private relationship with the issuer.

### 5.3 CRL / revocation

Signed Certificate Revocation Lists for compromised keys or retired agents. OSS and Pro clients can consume the CRL in airgapped mode.

### 5.4 License server

Runs the `trustchain-pro` license issuance endpoints with seat management, hardware binding, and audit. Deploy on your infra or consume as SaaS.

### 5.5 Compliance templates

SOC 2, HIPAA, FDA 21 CFR Part 11, EU AI Act — ready policy bundles, evidence collectors, and report templates. Maps Pro `ComplianceReport` output to specific control IDs.

### 5.6 Support, SLA, deployment

On-prem installer, air-gapped mirror, 24/7 response, dedicated engineer. Contact: [trustchain.dev](https://trustchain.dev).

> Internal implementation (CA HSM layout, registry DB schema, CRL signing cadence, SSO integration, tenant routing) is covered under NDA.

---

## 6. Comparison matrix

| Capability | OSS | Pro | Enterprise |
|---|---|---|---|
| Ed25519 sign / verify | Yes | Yes | Yes |
| `@tc.tool` decorator | Yes | Yes | Yes |
| `.tcreceipt` portable proof | Yes | Yes | Yes |
| Standards export (SCITT/W3C VC/in-toto) | Yes | Yes | Yes |
| Tool PKI / code hash checks | Yes | Yes | managed registry |
| Chain-head anchoring CLI | Yes | scheduled | managed custody |
| Chain-of-trust HEAD | Yes | Yes | Yes |
| Multi-tenant manager | Yes | Yes | Yes |
| Merkle verifiable log | Yes | Yes | Yes |
| LangChain / MCP / FastAPI adapters | Yes | Yes | Yes |
| Postgres verifiable chain store | Yes | Yes | Yes |
| Nonce replay protection (in-memory) | Yes | Yes | Yes |
| Redis HA nonces | — | Yes | Yes |
| PolicyEngine (YAML governance) | — | Yes | Yes |
| Streaming reasoning signatures | — | Yes | Yes |
| ExecutionGraph + HTML export | — | Yes | Yes |
| RFC 3161 TSA timestamps | — | Yes | Yes |
| FactSeal (provenance manifests) | — | Yes | Yes |
| KMS/HSM helpers | partial | Yes | Yes |
| ComplianceReport (HTML/PDF) | — | Yes | Yes |
| Analytics dashboards | — | Yes | Yes |
| Airgap bundle | — | Yes | Yes |
| Platform CA + leaf certificates | — | — | Yes |
| Public registry + CRL | — | — | Yes |
| SOC2 / HIPAA / EU AI Act templates | — | — | Yes |
| SLA, 24/7 support | — | — | Yes |
| License | MIT | Commercial (seat-based) | Commercial + SLA |

---

## 7. Security model (authoritative)

- **Signature:** Ed25519 over canonical JSON (RFC 8785-style: sorted keys, UTF-8, no whitespace).
- **Key storage:** local file (`~/.trustchain/keys/`) in OSS, external KMS/HSM in Pro/Enterprise.
- **Chain HEAD:** every new response signs `sha256(data) || prev_signature`; `TC_STRICT_CHAIN=1` enforces fail-closed behavior (ADR-SEC-005).
- **Nonce:** optional replay protection with monotonic counter + TTL; Redis HA in Pro.
- **Clock:** `response_timestamp` is signed; optional RFC 3161 TSA in Pro.
- **Certificates:** OSS operates with bare public keys; Platform adds X.509 chains anchored to the Platform Root CA.
- **Anchoring:** OSS exports portable chain-head checkpoints; Pro/Enterprise automate custody and external publication.
- **Revocation:** CRL (Platform) or manual key rotation (OSS/Pro).
- **Browser verification:** `.tcreceipt` files verify with WebCrypto (Ed25519) without any server call. See [`examples/verify.html`](../examples/verify.html).

ADRs of record: ADR-SEC-001 (Ed25519 over canonical JSON), ADR-SEC-002 (Postgres verifiable log), ADR-SEC-005 (strict-chain default), ADR-015 (signing architecture), ADR-016 (context layer).

---

## 8. Choosing a tier

- **You just want signed tool responses in one service.** → OSS.
- **You need YAML policies, streaming LLMs, auditor-ready reports, Redis HA.** → Pro.
- **You issue AI agents that outside parties (regulators, customers) must verify without trusting your servers.** → Enterprise (you need a CA).
- **You're building on top of TrustChain and want a partner SLA.** → Enterprise.

Start free, upgrade when the compliance or scale story requires it. OSS is forward-compatible with every upper tier — no data or code migration.

---

## 9. Where to go next

- Quick start: [`QUICK_START.md`](../QUICK_START.md)
- Product matrix: [`docs/PRODUCT_MATRIX.md`](PRODUCT_MATRIX.md)
- Receipt spec: [`docs/RECEIPTS.md`](RECEIPTS.md)
- Standards and alternatives: [`docs/STANDARDS.md`](STANDARDS.md)
- Tool PKI: [`docs/TOOL_PKI.md`](TOOL_PKI.md)
- Compliance evidence: [`docs/COMPLIANCE.md`](COMPLIANCE.md)
- Feature table (localized): [`docs/FEATURES.md`](FEATURES.md)
- Context layer (v3 DAG): [`docs/TRUSTCHAIN_CONTEXT_LAYER.md`](TRUSTCHAIN_CONTEXT_LAYER.md)
- `.tcreceipt` vs git: [`docs/TRUSTCHAIN_VS_GIT.md`](TRUSTCHAIN_VS_GIT.md)
- Wiki: [Architecture](wiki/Architecture.md), [Security](wiki/Security.md), [API Reference](wiki/API-Reference.md)
- Notebooks: [`examples/trustchain_tutorial.ipynb`](../examples/trustchain_tutorial.ipynb), [`trustchain_receipts.ipynb`](../examples/trustchain_receipts.ipynb), [`trustchain_advanced.ipynb`](../examples/trustchain_advanced.ipynb), [`trustchain_llm.ipynb`](../examples/trustchain_llm.ipynb), [`trustchain_full_demo.ipynb`](../examples/trustchain_full_demo.ipynb)

— Ed Cherednik &lt;edcherednik@gmail.com&gt;
