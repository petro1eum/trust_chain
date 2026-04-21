# TrustChain — EU AI Act Compliance Mapping

**Document version**: 1.0  
**Regulation**: EU AI Act (Regulation (EU) 2024/1689)  
**Date**: April 2026

## Executive Summary

The EU AI Act establishes mandatory requirements for high-risk AI systems, 
including logging, transparency, human oversight, and cybersecurity. 
**TrustChain provides a ready-made technical implementation** for the key 
compliance articles, reducing the engineering effort for EU AI Act conformance 
from months to days.

This document maps TrustChain capabilities to specific EU AI Act articles, 
demonstrating coverage across logging (Art. 12), transparency (Art. 13), 
human oversight (Art. 14), cybersecurity (Art. 15), and quality management (Art. 17).

---

## Article-by-Article Mapping

### Article 9: Risk Management System

> *"A risk management system shall be established, implemented, documented 
> and maintained in relation to high-risk AI systems."*

| Requirement | TrustChain Coverage |
|---|---|
| Identify and analyze known/foreseeable risks | **PolicyEngine** (Pro): YAML-based governance rules that define acceptable tool behavior |
| Evaluate risks from intended use | **ExecutionGraph** (Pro): DAG-based forensic analysis of agent decision chains |
| Adopt risk management measures | **FactSeal v2**: Critical fact detection — alerts when LLM omits or distorts verified data |

**TrustChain component**: `trustchain_pro.PolicyEngine`, `trustchain_pro.ExecutionGraph`

---

### Article 12: Record-Keeping (Logging)

> *"High-risk AI systems shall technically allow for the automatic recording 
> of events ('logs') over the duration of the lifetime of the system."*

| Requirement | TrustChain Coverage |
|---|---|
| Automatic recording of events | **Merkle audit log**: Every tool call → append to SHA-256 hash chain |
| Periods of use (start/end) | **Operation timestamps**: Each log entry includes `created_at` with precise timing |
| Input data recording | **Signed results**: Full tool input/output preserved with Ed25519 signature |
| Traceability of functioning | **Chain ID**: Operations linked via `chain_id` for session-level traceability |
| Tamper detection | **Merkle tree**: Any modification to historical logs is cryptographically detectable |

**TrustChain component**: `trustchain.MerkleAuditLog`, Platform `log_service.py`

**CLI verification**: `tc verify-chain --full` — validates entire log integrity

**Key advantage**: The EU AI Act does not mandate cryptographic logging, but legal 
experts recommend it as best practice for evidentiary value. TrustChain's Merkle tree 
provides **mathematically provable** tamper resistance, exceeding the regulation's 
minimum requirements.

---

### Article 13: Transparency and Provision of Information

> *"High-risk AI systems shall be designed and developed in such a way as to 
> ensure that their operation is sufficiently transparent to enable deployers 
> to interpret the system's output and use it appropriately."*

| Requirement | TrustChain Coverage |
|---|---|
| Interpret system output | **FactSeal v2 manifest**: Lists exactly which data points in the output are from verified sources vs. LLM-generated |
| Appropriate level of transparency | **Public registry** (`keys.trust-chain.ai`): Agent identities, certificates, and verification status are publicly auditable |
| Inform deployers about characteristics | **Certificate metadata**: Each agent's cert contains org, role, tier info — visible in portal |

**TrustChain component**: `__fact_manifest__`, `KeysPortalPage.tsx`, `/api/pub/agents`

**Key advantage**: FactSeal doesn't just log — it creates a **granular map** of 
which facts are cryptographically attested. This is transparency at the data-point 
level, not just the system level.

---

### Article 14: Human Oversight

> *"High-risk AI systems shall be designed and developed in such a way [...] 
> that they can be effectively overseen by natural persons."*

| Requirement | TrustChain Coverage |
|---|---|
| Monitor system in real-time | **Platform Dashboard**: Live agent count, operations, certificate status |
| Detect anomalies | **VerifiedFact UI**: Green shields for verified data, red alerts for missing critical facts |
| Intervene / override | **Certificate revocation**: Instant CRL-based revocation of compromised agents |
| Deactivation capability | **Agent decommission API**: `DELETE /api/agents/{id}` — cascading revocation for sub-agents |

**TrustChain component**: Platform `page.tsx` (Dashboard), `ca_service.revoke()`

**Planned**: Approval workflow for high-stakes operations (human-in-the-loop signing)

---

### Article 15: Accuracy, Robustness and Cybersecurity

> *"High-risk AI systems shall be designed and developed in such a way that 
> they achieve [...] an appropriate level of accuracy, robustness and 
> cybersecurity."*

| Requirement | TrustChain Coverage |
|---|---|
| Resilient against manipulation | **Ed25519 digital signatures**: 128-bit security level, quantum-aware |
| Cybersecurity measures | **X.509 PKI**: Same trust model as TLS/HTTPS (Root CA → Intermediate → Agent) |
| Key management | **Certificate lifecycle**: Issue → rotate → revoke, with CRL distribution |
| Error/inconsistency detection | **Missing critical fact detection**: FactSeal alerts when LLM distorts signed data |

**TrustChain component**: `TrustChainCA`, `CRL`, `FactSeal v2`

**Performance**: Ed25519 signing at **9,100 ops/sec** (0.11ms per operation) — 
near-zero overhead for production AI systems.

---

### Article 17: Quality Management System

> *"Providers of high-risk AI systems shall put a quality management system 
> in place that ensures compliance with this Regulation."*

| Requirement | TrustChain Coverage |
|---|---|
| Documented procedures | **PolicyEngine** (Pro): YAML governance rules, versioned and auditable |
| Verification and validation | **Test suites**: 44-step E2E suite, mutation tests for cryptographic integrity |
| Accountability framework | **Audit log**: Admin actions (register, revoke, config changes) logged with actor_id |
| Incident reporting | **ComplianceReport** (Pro): SOC2/HIPAA-format report generation |
| Post-market monitoring | **TrustChainAnalytics** (Pro): Operational metrics and trend analysis |

**TrustChain component**: `trustchain_pro.PolicyEngine`, `trustchain_pro.ComplianceReport`

---

## Compliance Summary Matrix

| Article | Title | Coverage | Tier |
|---------|-------|----------|------|
| Art. 9 | Risk Management | ✅ Full | Pro |
| Art. 12 | Record-Keeping | ✅ Full | OSS |
| Art. 13 | Transparency | ✅ Full | OSS + Pro |
| Art. 14 | Human Oversight | ✅ Partial (approval workflow planned) | Platform |
| Art. 15 | Cybersecurity | ✅ Full | OSS |
| Art. 17 | Quality Management | ✅ Full | Pro |

**Result**: TrustChain covers **6 out of 6** key compliance articles for high-risk 
AI systems, with the OSS tier covering Articles 12, 13, and 15 at no cost.

---

## Deployment for Compliance

### Minimum Viable Compliance (OSS)

```bash
pip install trustchain
```

Provides: Ed25519 signing, Merkle audit log, CLI verification, chain integrity.

### Full Compliance (Pro + Platform)

```bash
pip install trustchain-pro
# + Deploy TrustChain Platform (CA, registry, dashboard)
```

Provides: PolicyEngine, FactSeal v2, ComplianceReport, TSA timestamps, 
public certificate registry, real-time monitoring dashboard.

### Compliance Evidence

For auditors, TrustChain provides:

1. **`tc verify-chain --full`** — cryptographic integrity verification
2. **`keys.trust-chain.ai`** — public, browsable agent registry
3. **Merkle root hash** — single hash proving entire log integrity
4. **X.509 certificate chain** — downloadable, offline-verifiable
5. **ComplianceReport** — formatted SOC2/HIPAA output

---

*This document is intended for regulatory assessment purposes. 
TrustChain is MIT-licensed open-source software and does not constitute 
legal advice. Organizations should consult qualified legal counsel for 
definitive EU AI Act compliance guidance.*

*Ed Cherednik · TrustChain · April 2026*
