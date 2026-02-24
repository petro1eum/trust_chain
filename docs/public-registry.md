# TrustChain Public Certificate Registry

> **Zero-trust, offline-verifiable signatures for AI agents.**

The Public Registry exposes three read-only, unauthenticated endpoints so **any external developer** can verify that a signature was produced by a registered TrustChain agent — without trusting our API blindly and without sending data to our servers.

---

## How It Works

TrustChain Platform acts as a **Certificate Authority (CA)** for AI agents.  
Every registered agent receives an **X.509 certificate** signed by the TrustChain Platform CA.

To verify an agent's signature:

1. Download the agent's **X.509 certificate** from the registry
2. Verify the certificate against the **TrustChain Platform CA** (local, offline)
3. Check the certificate is not on the **CRL** (Certificate Revocation List)
4. Extract the **Ed25519 public key** from the verified certificate
5. Verify the signature locally — **no server call needed**

---

## Endpoints

All endpoints are public. No API key required.

### `GET /api/pub/agents/{agent_id}/cert`

Returns the PEM-encoded X.509 certificate issued to the agent.

```bash
curl https://app.trust-chain.ai/api/pub/agents/my-agent/cert
```

```
-----BEGIN CERTIFICATE-----
MIIBxTCCAW...
-----END CERTIFICATE-----
```

### `GET /api/pub/ca`

Returns the PEM-encoded TrustChain Platform CA certificate.  
Cache this — it rarely changes.

```bash
curl https://app.trust-chain.ai/api/pub/ca
```

### `GET /api/pub/crl`

Returns the current PEM-encoded Certificate Revocation List.  
Refresh periodically (recommended: every 5 minutes in production).

```bash
curl https://app.trust-chain.ai/api/pub/crl
```

---

## Verification Example (Python)

```python
import httpx
from cryptography.x509 import load_pem_x509_certificate, load_pem_x509_crl
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.x509.ocsp import OCSPCertStatus

BASE = "https://app.trust-chain.ai/api/pub"

# 1. Download certificates (cache ca_pem and crl_pem in production)
agent_cert_pem = httpx.get(f"{BASE}/agents/my-agent/cert").text
ca_pem         = httpx.get(f"{BASE}/ca").text
crl_pem        = httpx.get(f"{BASE}/crl").text

# 2. Parse
agent_cert = load_pem_x509_certificate(agent_cert_pem.encode())
ca_cert    = load_pem_x509_certificate(ca_pem.encode())
crl        = load_pem_x509_crl(crl_pem.encode())

# 3. Verify certificate was signed by TrustChain Platform CA
ca_cert.public_key().verify(
    agent_cert.signature,
    agent_cert.tbs_certificate_bytes,
    # Ed25519 has no extra params
)

# 4. Check revocation
assert crl.get_revoked_certificate_by_serial_number(agent_cert.serial_number) is None, \
    "Agent certificate has been revoked!"

# 5. Extract public key from the trusted certificate
public_key: Ed25519PublicKey = agent_cert.public_key()  # type: ignore

# 6. Verify the signature locally — no network call
public_key.verify(signature_bytes, data_bytes)
# Raises cryptography.exceptions.InvalidSignature if tampered
```

---

## Verification Example (Node.js / TypeScript)

```typescript
import { X509Certificate } from 'crypto'; // Node 15+

const BASE = 'https://app.trust-chain.ai/api/pub';

const [agentCertPem, caPem] = await Promise.all([
  fetch(`${BASE}/agents/my-agent/cert`).then(r => r.text()),
  fetch(`${BASE}/ca`).then(r => r.text()),
]);

const agentCert = new X509Certificate(agentCertPem);
const caCert    = new X509Certificate(caPem);

// Verify chain
const chainValid = agentCert.verify(caCert.publicKey);
if (!chainValid) throw new Error('Certificate chain invalid');

// Verify signature using the trusted public key
const ok = crypto.verify(null, dataBuffer, agentCert.publicKey, signatureBuffer);
if (!ok) throw new Error('Signature invalid');
```

---

## Trust Model

```
TrustChain Root CA  (self-signed, pinneable)
    └── TrustChain Platform CA  ← GET /api/pub/ca
            └── Agent Certificate  ← GET /api/pub/agents/{id}/cert
                    └── Ed25519 Public Key  (extracted locally)
```

**You trust the Platform CA, not our API responses.**  
Pin the CA certificate in your application and rotate it only when we announce a CA rotation.

---

## Why Not Return a Raw Public Key?

Returning just `{ "public_key": "..." }` would require you to **trust our HTTPS response blindly** — defeating the entire point of cryptographic verification. By returning an X.509 certificate, you can verify the signature chain yourself and be certain the key belongs to a legitimate TrustChain agent.

This is the same model used by:
- **Let's Encrypt** (download cert → verify against ISRG Root X1)
- **Apple App Store** (app signatures → verified against Apple Root CA)
- **TLS/HTTPS** (server cert → verified against browser trust store)

---

## Security Notes

- **No server-side verification:** Do not send your data or signatures to our servers. Verify locally.
- **CRL freshness:** A revoked agent's certificate is added to the CRL immediately. Check CRL on every session, not every request.
- **CA pinning:** For high-security deployments, pin the CA certificate hash and alert on changes.
