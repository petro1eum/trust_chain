# TrustChain — EU AI Act Compliance Mapping

**Document version**: 1.0  
**Regulation**: EU AI Act (Regulation (EU) 2024/1689)  
**Date**: April 2026

## Executive Summary

The EU AI Act establishes mandatory requirements for high-risk AI systems, 
including logging, transparency, human oversight, and cybersecurity. 
**TrustChain provides technical evidence primitives** for key compliance
articles: signed tool outputs, portable `.tcreceipt` files, chain verification,
standards exports, and external anchors.

This document maps TrustChain capabilities to specific EU AI Act articles, 
demonstrating support across logging (Art. 12), transparency (Art. 13), human
oversight (Art. 14), cybersecurity (Art. 15), and quality management (Art. 17).
It is not legal advice and does not make a deployment compliant by itself.

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
| Automatic recording of events | **Signed responses + ChainStore**: every material tool call can be recorded |
| Periods of use (start/end) | **Operation timestamps**: each record includes signed `response_timestamp` and store timestamp |
| Input/output evidence | **`.tcreceipt`**: portable proof of a specific signed tool output |
| Traceability of functioning | **Parent signatures / chain HEAD**: ordered operations are linked |
| Tamper detection | **`tc chain-verify` + `tc anchor`**: detect local link breaks and whole-chain rewrites against external checkpoints |

**TrustChain component**: `SignedResponse`, `ChainStore`, `.tcreceipt`, `tc anchor`

**CLI verification**: `tc chain-verify`, `tc receipt verify`, `tc anchor verify`

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
| Interpret system output | **Receipts and standards export**: a verifier can inspect signed envelope, signer, timestamp, and chain metadata |
| Appropriate level of transparency | **Public registry** (`keys.trust-chain.ai`): agent/tool identities, certificates, and revocation status are auditable |
| Inform deployers about characteristics | **Certificate metadata + Tool PKI**: signer identity, tool code hash, permissions, and version can be attached |

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
| Resilient against manipulation | **Ed25519 digital signatures**: strong modern signature primitive |
| Cybersecurity measures | **X.509 PKI**: Same trust model as TLS/HTTPS (Root CA → Intermediate → Agent) |
| Key management | **Certificate lifecycle**: Issue → rotate → revoke, with CRL distribution |
| Tool integrity | **Tool PKI**: source-code hash binding catches unexpected tool changes |
| Error/inconsistency detection | **Receipts + chain verification**: tampering, wrong key, stale evidence, and broken parent links are detectable |

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
| Art. 9 | Risk Management | Technical support | Pro |
| Art. 12 | Record-Keeping | Strong evidence primitives | OSS |
| Art. 13 | Transparency | Strong evidence primitives | OSS + Platform |
| Art. 14 | Human Oversight | Partial / workflow-dependent | Pro + Enterprise |
| Art. 15 | Cybersecurity | Strong evidence primitives | OSS + Enterprise |
| Art. 17 | Quality Management | Report/workflow support | Pro + Enterprise |

**Result**: TrustChain provides strong technical evidence for the main logging,
traceability, transparency, and integrity requirements. Final compliance depends
on deployment, retention, access control, risk management, and legal review.

---

## Deployment for Compliance

### Minimum Viable Compliance (OSS)

```bash
pip install trustchain
```

Provides: Ed25519 signing, `.tcreceipt`, chain verification, standards export,
basic anchoring, and offline verification.

### Full Compliance (Pro + Platform)

```bash
pip install trustchain-pro
# + Deploy TrustChain Platform (CA, registry, dashboard)
```

Provides: PolicyEngine, FactSeal v2, ComplianceReport, TSA timestamps, 
public certificate registry, real-time monitoring dashboard.

### Compliance Evidence

For auditors, TrustChain provides:

1. **`tc chain-verify`** — local chain integrity verification
2. **`tc receipt verify`** — portable proof verification
3. **`tc anchor verify`** — compare current chain to an external checkpoint
4. **`tc standards export`** — SCITT/W3C VC/in-toto evidence exports
5. **`keys.trust-chain.ai`** — public certificate and revocation registry
6. **X.509 certificate chain** — downloadable, offline-verifiable identity
7. **ComplianceReport** — formatted SOC2/HIPAA/EU AI Act output (Pro)

---

*This document is intended for regulatory assessment purposes. 
TrustChain is MIT-licensed open-source software and does not constitute 
legal advice. Organizations should consult qualified legal counsel for 
definitive EU AI Act compliance guidance.*

*Ed Cherednik · TrustChain · April 2026*
