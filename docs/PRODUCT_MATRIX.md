# TrustChain product matrix — OSS, Pro, SaaS

## OSS — `trustchain` (PyPI, MIT)

- `@tc.tool` decorator, `TrustChain.sign` / `verify`, `TrustChainVerifier`  
- File-backed `.trustchain/` chain, CLI `tc` (`tc cert request` — шаги к leaf cert на Platform, `tc-verify` — офлайн-проверка `jsonl.gz`)  
- `.tcreceipt` portable proof: `tc receipt build/show/verify`, browser/offline verification  
- Standards export: `tc standards export --format scitt|w3c-vc|intoto`, plus `trustchain.standards.*` Python adapters  
- Chain anchoring: `tc anchor export` / `tc anchor verify` for external chain-head checkpoints  
- Tool PKI: `ToolCertificate`, `ToolRegistry`, source-code hash checks, local certificate store  
- Merkle / verifiable log modes (Postgres backend optional)  
- Integrations: LangChain, MCP, FastAPI, Pydantic v2, OpenTelemetry  

## Pro — `trustchain-pro` (commercial)

- **License:** Ed25519 v2 token (`TRUSTCHAIN_PRO_LICENSE`); issue via `tc-license print-dev-token` (dev) or license server.  
- **Modules:** PolicyEngine, StreamingReasoningChain, Redis HA nonces, ExecutionGraph, TSA, FactSeal, KMS helpers, ComplianceReport, Analytics, Airgap, ChainExplorer HTML export.  
- **Note:** LangChain / MCP adapters, `.tcreceipt`, standards exports, Tool PKI, and basic anchoring ship in **OSS**; Pro adds governance, reporting, scheduled workflows, and enterprise hardening on top.

## SaaS — `TrustChain_Platform`

- Platform **Root / Intermediate CA**, CRL, public registry (`/api/pub/*`)  
- Agent certificate issuance and revocation  
- Tool/agent registry, CRL-backed revocation, and cross-company trust distribution  
- Transparency/custody path for anchors, witnesses, retention, and third-party evidence stores  
- Chrome extension (public verification UX)  
- License server (Postgres + `tc-license` CLI)  

## Agent product — `TrustChain_Agent`

- Chat BFF + SSE, tool execution with **real** `trustchain` signing  
- Panel UI, optional `trustchain-pro` routes under `/api/trustchain-pro/*`  
