# TrustChain tests

This directory contains pytest suites for the TrustChain OSS library (`trustchain/`).

## Layout

| File | Focus |
|------|--------|
| `conftest.py` | Shared fixtures |
| `test_v2_basic.py` | Core v2 API smoke |
| `test_verifiable_log.py` | Append-only verifiable log + Merkle |
| `test_pg_verifiable_log.py` | PostgreSQL verifiable backend |
| `test_merkle.py` | Merkle tree |
| `test_cli.py` | `tc` CLI (`checkpoint`, `branch`, `tag`, `refs`, …) |
| `test_v3_compensations.py` | `trustchain.v3.compensations` |
| `test_migrate_v3.py` | `tc migrate-v3`, v2→v3 CAS (`migrate_v2_linear_to_v3`) |
| `test_v3_cas_io.py` | `trustchain.v3.cas_io` (чтение объектов CAS) |
| `test_manifest_hash.py` | `tc manifest hash`, `tool_manifest_sha256_hex` |
| `test_chain_of_trust.py` | Signature chain / parent links |
| `test_e2e.py` | End-to-end sign → verify |
| `test_verifier.py` | `TrustChainVerifier` |
| `test_file_storage.py` | `FileStorage` |
| `test_async.py`, `test_async_core.py` | AsyncTrustChain |
| `test_session.py` | Session / exports |
| `test_certificates.py`, `test_certificate.py`, `test_x509_pki.py` | PKI / tool certs |
| `test_tc_verify_pkix.py` | `tc-verify --full-chain` (local PEM bundle) |
| `test_nonce_storage.py` | Nonce backends |
| `test_events.py` | CloudEvents |
| `test_tenants.py` | Multi-tenant |
| `test_policy.py` | OSS policy hooks |
| `test_key_rotation.py` | Key rotation |
| `test_schemas.py` | Schema helpers |
| `test_server.py` | REST server |
| `test_pytest_plugin.py` | pytest plugin |
| `test_langchain.py`, `test_langsmith.py` | LangChain / LangSmith |
| `test_pydantic_v2.py` | Pydantic v2 |
| `test_mcp.py` | MCP integration |
| `test_opentelemetry.py` | OpenTelemetry |
| `test_fastapi_integration.py`, `test_flask_integration.py`, `test_django_integration.py` | Web framework adapters |
| `test_llm_tool_calling.py`, `test_llm_integrations.py`, `test_real_llm_clean.py`, `test_integrations_real.py` | LLM / API (optional keys) |
| `test_examples.py` | Example scripts |
| `test_legal_rag.py` | Legal RAG demo path |
| `test_onaidocs_integration.py` | OnaiDocs-style embed |

## Run

```bash
pip install -e ".[dev]"
pytest tests/ -q
```

### With coverage (local only; do not commit `coverage.xml`)

```bash
pytest tests/ --cov=trustchain --cov-report=term-missing
```

### Integration / Postgres

Some tests need `TC_VERIFIABLE_LOG_DSN` or Docker Postgres (see `test_pg_verifiable_log.py` and CI workflows).

## Principles

- Security-sensitive paths use real Ed25519 where the test name implies crypto behaviour.
- Tests that call external LLM APIs are gated on environment variables (`OPENAI_API_KEY`, etc.).
